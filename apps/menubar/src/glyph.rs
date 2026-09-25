//! The menu bar glyph: a ring with a tick, an exclamation mark or a dash in
//! it, mirroring the state (spec section 8.1).
//!
//! It is drawn here rather than shipped as image files, so the three states
//! cannot drift apart and nothing needs a drawing program. It is a template
//! image: black on transparent, which macOS tints for a light or a dark menu
//! bar. Placeholder art.

use crate::popover::Orb;

/// The side of the glyph in pixels: 18 points at twice the resolution, the
/// height macOS gives a menu bar icon.
pub const SIZE: u32 = 36;

/// Which mark sits inside the ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mark {
    /// All clear.
    Tick,
    /// Something asks for the user.
    Exclamation,
    /// Protection is off, or AgentSweep is updating.
    Dash,
}

impl Mark {
    /// The mark an orb shows.
    pub fn of(orb: Orb) -> Mark {
        match orb {
            Orb::Clear => Mark::Tick,
            Orb::Attention => Mark::Exclamation,
            Orb::Off | Orb::Updating => Mark::Dash,
        }
    }
}

/// A point in pixel space.
type Point = (f32, f32);

/// The distance from `p` to the segment from `a` to `b`.
fn to_segment(p: Point, a: Point, b: Point) -> f32 {
    let (dx, dy) = (b.0 - a.0, b.1 - a.1);
    let length = dx * dx + dy * dy;
    let t = if length > 0.0 {
        (((p.0 - a.0) * dx + (p.1 - a.1) * dy) / length).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let (x, y) = (a.0 + t * dx - p.0, a.1 + t * dy - p.1);
    (x * x + y * y).sqrt()
}

/// How much of a pixel a stroke of `half` half-width covers at `distance`
/// from its centre line, with one pixel of anti-aliasing.
fn coverage(distance: f32, half: f32) -> f32 {
    (half + 0.5 - distance).clamp(0.0, 1.0)
}

/// The glyph as RGBA pixels, `SIZE` by `SIZE`, row by row.
pub fn pixels(mark: Mark) -> Vec<u8> {
    let s = SIZE as f32;
    let centre = (s / 2.0, s / 2.0);
    let ring = s / 2.0 - 2.5;
    let stroke = 1.6;
    let segments: Vec<(Point, Point, f32)> = match mark {
        Mark::Tick => vec![
            ((s * 0.31, s * 0.52), (s * 0.45, s * 0.66), stroke),
            ((s * 0.45, s * 0.66), (s * 0.70, s * 0.36), stroke),
        ],
        Mark::Exclamation => vec![
            ((s * 0.5, s * 0.27), (s * 0.5, s * 0.56), stroke),
            ((s * 0.5, s * 0.71), (s * 0.5, s * 0.71), stroke + 0.4),
        ],
        Mark::Dash => vec![((s * 0.32, s * 0.5), (s * 0.68, s * 0.5), stroke)],
    };

    let mut out = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for row in 0..SIZE {
        for column in 0..SIZE {
            let p = (column as f32 + 0.5, row as f32 + 0.5);
            let from_centre = ((p.0 - centre.0).powi(2) + (p.1 - centre.1).powi(2)).sqrt();
            let mut alpha = coverage((from_centre - ring).abs(), stroke / 2.0 + 0.3);
            for (a, b, width) in &segments {
                alpha = alpha.max(coverage(to_segment(p, *a, *b), *width));
            }
            out.extend_from_slice(&[0, 0, 0, (alpha * 255.0).round() as u8]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alpha(pixels: &[u8], column: u32, row: u32) -> u8 {
        pixels[((row * SIZE + column) * 4 + 3) as usize]
    }

    #[test]
    fn each_state_has_its_own_mark() {
        assert_eq!(Mark::of(Orb::Clear), Mark::Tick);
        assert_eq!(Mark::of(Orb::Attention), Mark::Exclamation);
        assert_eq!(Mark::of(Orb::Off), Mark::Dash);
        assert_eq!(Mark::of(Orb::Updating), Mark::Dash);
    }

    /// A template image is black with an alpha channel and nothing else, so
    /// macOS can tint it for either menu bar.
    #[test]
    fn every_glyph_is_a_template_of_the_documented_size() {
        for mark in [Mark::Tick, Mark::Exclamation, Mark::Dash] {
            let pixels = pixels(mark);
            assert_eq!(pixels.len(), (SIZE * SIZE * 4) as usize);
            assert!(
                pixels
                    .chunks(4)
                    .all(|p| p[0] == 0 && p[1] == 0 && p[2] == 0)
            );
            assert!(
                pixels.chunks(4).any(|p| p[3] == 255),
                "{mark:?} draws something"
            );
            assert_eq!(alpha(&pixels, 0, 0), 0, "{mark:?} leaves the corner clear");
        }
    }

    #[test]
    fn the_three_marks_are_told_apart_by_where_they_draw() {
        let tick = pixels(Mark::Tick);
        let exclamation = pixels(Mark::Exclamation);
        let dash = pixels(Mark::Dash);
        assert_ne!(tick, exclamation);
        assert_ne!(exclamation, dash);
        assert_ne!(tick, dash);

        let middle = SIZE / 2;
        // The dash crosses the middle row; the exclamation mark does not reach
        // its sides.
        assert_eq!(alpha(&dash, 13, middle), 255);
        assert_eq!(alpha(&exclamation, 13, middle), 0);
        // The exclamation mark stands in the middle column, above the middle.
        assert_eq!(alpha(&exclamation, middle, 12), 255);
        assert_eq!(alpha(&dash, middle, 12), 0);
        // The tick's corner is low and left of the middle.
        assert_eq!(alpha(&tick, 16, 23), 255);
        assert_eq!(alpha(&dash, 16, 23), 0);
    }
}
