//! What normal was, and how far from it something is.
//!
//! An exponentially weighted moving average with its variance, updated one sample at a time. Cumulative while
//! it is young, so an hour's traffic is not compared against a single earlier hour and called a spike; then
//! weighted, with about a week's memory for hourly samples, so that last month does not outvote this week.
//!
//! # Why the arithmetic is written out here
//!
//! Because it is the same arithmetic the macOS build uses, and it has to stay the same. A spike is a spike on
//! both or the two tools disagree about what a machine is doing — which is worse than either of them being
//! wrong, because each is confirmed by the other's silence.

/// What normal looks like for one thing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Baseline {
    /// The average, weighted towards recent samples.
    pub mean: f64,
    /// Its variance, weighted the same way.
    pub variance: f64,
    /// How many samples it is made of.
    pub samples: u32,
}

impl Baseline {
    /// A baseline of one sample.
    pub fn first(sample: f64) -> Self {
        Self {
            mean: sample,
            variance: 0.0,
            samples: 1,
        }
    }

    /// The standard deviation, with a floor under it.
    ///
    /// The floor is what stops a thing that has been perfectly steady from calling its first variation an
    /// emergency: with no floor, a variance of zero makes every deviation infinite.
    pub fn deviation(&self, floor: f64) -> f64 {
        self.variance.sqrt().max(floor)
    }

    /// How many deviations above normal a sample is.
    ///
    /// Negative below it, which is never an alert: nobody wants to be told that a process was quieter than
    /// usual.
    pub fn z_score(&self, sample: f64, floor: f64) -> f64 {
        (sample - self.mean) / self.deviation(floor)
    }
}

/// Folds one sample into a baseline.
///
/// The weight is `1/(n+1)` while young and never smaller than `0.02`, which is about a week of hourly samples.
/// A newer sample therefore always moves the average a little, and no amount of history can make a baseline
/// unable to learn.
pub fn update(baseline: Option<Baseline>, sample: f64) -> Baseline {
    let Some(mut baseline) = baseline.filter(|baseline| baseline.samples > 0) else {
        return Baseline::first(sample);
    };
    let weight = (1.0 / f64::from(baseline.samples + 1)).max(0.02);
    let difference = sample - baseline.mean;
    let increment = weight * difference;
    baseline.mean += increment;
    baseline.variance = (1.0 - weight) * (baseline.variance + difference * increment);
    baseline.samples = baseline.samples.saturating_add(1);
    baseline
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_sample_is_the_baseline() {
        let baseline = update(None, 100.0);
        assert_eq!(baseline.mean, 100.0);
        assert_eq!(baseline.variance, 0.0);
        assert_eq!(baseline.samples, 1);
    }

    /// An hour's traffic must not be compared against a single earlier hour and called a spike, so the average
    /// is cumulative while it is young.
    #[test]
    fn a_young_baseline_is_the_average_so_far() {
        let mut baseline = None;
        for sample in [10.0, 20.0, 30.0] {
            baseline = Some(update(baseline, sample));
        }
        let baseline = baseline.expect("three samples");
        assert_eq!(baseline.samples, 3);
        assert!((baseline.mean - 20.0).abs() < 0.001, "{}", baseline.mean);
    }

    /// And no amount of history can make it unable to learn: the weight never falls below a week's worth.
    #[test]
    fn an_old_baseline_still_moves() {
        let mut baseline = Baseline::first(100.0);
        for _ in 0..5_000 {
            baseline = update(Some(baseline), 100.0);
        }
        let before = baseline.mean;
        baseline = update(Some(baseline), 200.0);
        assert!(baseline.mean > before, "an old baseline should still move");
        // Two per cent of the difference, which is the floor on the weight.
        assert!(
            (baseline.mean - (before + 2.0)).abs() < 0.1,
            "{}",
            baseline.mean
        );
    }

    /// With no floor, something that has been perfectly steady calls its first variation infinite.
    #[test]
    fn a_steady_thing_needs_a_floor_under_its_deviation() {
        let mut baseline = Baseline::first(100.0);
        for _ in 0..50 {
            baseline = update(Some(baseline), 100.0);
        }
        assert!(baseline.variance < 0.001, "{}", baseline.variance);
        // Without a floor this is infinite; with one it is a number.
        let score = baseline.z_score(110.0, 10.0);
        assert!(score.is_finite(), "{score}");
        assert!((score - 1.0).abs() < 0.1, "{score}");
    }

    /// Nobody wants to be told that a process was quieter than usual.
    #[test]
    fn below_normal_is_never_a_spike() {
        let mut baseline = Baseline::first(100.0);
        for sample in [90.0, 110.0, 105.0, 95.0] {
            baseline = update(Some(baseline), sample);
        }
        assert!(baseline.z_score(10.0, 1.0) < 0.0);
    }

    #[test]
    fn a_real_spike_scores_high() {
        let mut baseline = None;
        for _ in 0..30 {
            baseline = Some(update(baseline, 1_000.0));
        }
        for sample in [1_100.0, 900.0, 1_050.0] {
            baseline = Some(update(baseline, sample));
        }
        let baseline = baseline.expect("samples");
        assert!(baseline.z_score(50_000.0, 100.0) > 3.0);
    }
}
