//! Where the popover and the Findings window open (spec section 8.1).
//!
//! The popover opens under the menu bar icon that was clicked, on whatever
//! display that icon is on. The Findings window opens centred on the display
//! that holds the pointer, the one the user is working on.
//!
//! On macOS the displays share one space in points, with the main display's
//! top left corner at the origin: a display left of the main one has a
//! negative x, one above it a negative y. What the operating system reports
//! in physical pixels is each display's points times that display's own
//! scale factor, so it is turned back into points with that display's factor
//! before anything is compared, and every position computed here is in
//! points.

/// A display as the operating system reports it: its origin and size in
/// physical pixels, scaled by its own factor, and that factor.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Display {
    /// The left edge, in physical pixels.
    pub x: i32,
    /// The top edge, in physical pixels.
    pub y: i32,
    /// The width, in physical pixels.
    pub width: u32,
    /// The height, in physical pixels.
    pub height: u32,
    /// The display's scale factor: 2 on a Retina display, 1 otherwise.
    pub scale: f64,
}

/// The menu bar icon's rectangle as the tray reports it: in physical pixels,
/// scaled by the factor of the display the icon is on.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Icon {
    /// The left edge, in physical pixels.
    pub x: f64,
    /// The top edge, in physical pixels.
    pub y: f64,
    /// The width, in physical pixels.
    pub width: f64,
    /// The height, in physical pixels.
    pub height: f64,
}

/// A size in points.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Size {
    /// The width, in points.
    pub width: f64,
    /// The height, in points.
    pub height: f64,
}

/// A top left corner in points, where a window is placed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Point {
    /// The left edge, in points.
    pub x: f64,
    /// The top edge, in points.
    pub y: f64,
}

/// A display's bounds in points: left, top, width, height.
fn bounds(display: Display) -> (f64, f64, f64, f64) {
    let scale = scale_of(display.scale);
    (
        f64::from(display.x) / scale,
        f64::from(display.y) / scale,
        f64::from(display.width) / scale,
        f64::from(display.height) / scale,
    )
}

/// A usable scale factor: one where the operating system gave none.
fn scale_of(scale: f64) -> f64 {
    match scale.is_finite() && scale > 0.0 {
        true => scale,
        false => 1.0,
    }
}

/// `value` kept between `low` and `high`; `low` wins where the span is too
/// small, so a window's top left corner is always on its display.
fn keep_within(value: f64, low: f64, high: f64) -> f64 {
    value.min(high).max(low)
}

/// Where the popover opens: centred under the icon that was clicked, kept
/// inside the display the icon is on.
pub fn popover_position(icon: Icon, display: Display, popover: Size) -> Point {
    let scale = scale_of(display.scale);
    let (left, top, width, height) = bounds(display);
    let centre = (icon.x + icon.width / 2.0) / scale;
    let icon_bottom = (icon.y + icon.height) / scale;
    Point {
        x: keep_within(
            centre - popover.width / 2.0,
            left,
            left + width - popover.width,
        ),
        y: keep_within(icon_bottom, top, top + height - popover.height),
    }
}

/// Where the Findings window opens: centred on the display under the pointer.
pub fn window_position(display: Display, window: Size) -> Point {
    let (left, top, width, height) = bounds(display);
    Point {
        x: left + ((width - window.width) / 2.0).max(0.0),
        y: top + ((height - window.height) / 2.0).max(0.0),
    }
}

/// The pointer in points, from the position the operating system reports:
/// on macOS that is scaled by the main display's factor, whatever display
/// the pointer is on.
pub fn pointer_in_points(x: f64, y: f64, main_scale: f64) -> Point {
    let scale = scale_of(main_scale);
    Point {
        x: x / scale,
        y: y / scale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POPOVER: Size = Size {
        width: 300.0,
        height: 300.0,
    };

    /// The main display: 1512 by 982 points on a Retina panel.
    const MAIN: Display = Display {
        x: 0,
        y: 0,
        width: 3024,
        height: 1964,
        scale: 2.0,
    };

    /// A display of 1920 by 1080 points left of the main one.
    const LEFT: Display = Display {
        x: -1920,
        y: 0,
        width: 1920,
        height: 1080,
        scale: 1.0,
    };

    /// An icon 32 points wide under a 24 point menu bar, reported in the
    /// physical pixels of a display with `scale`.
    fn icon_at(left: f64, top: f64, scale: f64) -> Icon {
        Icon {
            x: left * scale,
            y: top * scale,
            width: 32.0 * scale,
            height: 24.0 * scale,
        }
    }

    #[test]
    fn the_popover_opens_under_the_icon_on_the_main_display() {
        let at = popover_position(icon_at(1000.0, 0.0, 2.0), MAIN, POPOVER);
        assert_eq!(at, Point { x: 866.0, y: 24.0 });
    }

    /// A display left of the main one has a negative x; the popover opens
    /// there, not clamped onto the main display.
    #[test]
    fn the_popover_opens_on_a_display_left_of_the_main_one() {
        let at = popover_position(icon_at(-800.0, 0.0, 1.0), LEFT, POPOVER);
        assert_eq!(at, Point { x: -934.0, y: 24.0 });
    }

    /// A display above the main one has a negative y; the popover opens
    /// under its menu bar, with the display's own scale factor.
    #[test]
    fn the_popover_opens_on_a_display_above_the_main_one() {
        let above = Display {
            x: 0,
            y: -2160,
            width: 3840,
            height: 2160,
            scale: 2.0,
        };
        let at = popover_position(icon_at(1500.0, -1080.0, 2.0), above, POPOVER);
        assert_eq!(
            at,
            Point {
                x: 1366.0,
                y: -1056.0
            }
        );
    }

    /// An icon near the right edge: the popover stays inside the display.
    #[test]
    fn the_popover_stays_inside_the_display_near_its_right_edge() {
        let at = popover_position(icon_at(1470.0, 0.0, 2.0), MAIN, POPOVER);
        assert_eq!(at, Point { x: 1212.0, y: 24.0 });
        let right = Display {
            x: 1512,
            y: 0,
            width: 2560,
            height: 1440,
            scale: 1.0,
        };
        let at = popover_position(icon_at(4040.0, 0.0, 1.0), right, POPOVER);
        assert_eq!(at, Point { x: 3772.0, y: 24.0 });
    }

    /// And near the left edge of a display left of the main one.
    #[test]
    fn the_popover_stays_inside_the_display_near_its_left_edge() {
        let at = popover_position(icon_at(-1915.0, 0.0, 1.0), LEFT, POPOVER);
        assert_eq!(
            at,
            Point {
                x: -1920.0,
                y: 24.0
            }
        );
    }

    #[test]
    fn the_window_opens_centred_on_a_secondary_display() {
        let window = Size {
            width: 820.0,
            height: 640.0,
        };
        let secondary = Display {
            x: -2560,
            y: -200,
            width: 2560,
            height: 1440,
            scale: 1.0,
        };
        assert_eq!(
            window_position(secondary, window),
            Point {
                x: -1690.0,
                y: 200.0
            }
        );
        let retina = Display {
            x: 3024,
            y: 0,
            width: 3840,
            height: 2160,
            scale: 2.0,
        };
        assert_eq!(
            window_position(retina, window),
            Point {
                x: 2062.0,
                y: 220.0
            }
        );
    }

    /// A window larger than its display keeps its top left corner on it.
    #[test]
    fn a_window_larger_than_the_display_starts_at_its_corner() {
        let small = Display {
            x: -800,
            y: 0,
            width: 800,
            height: 600,
            scale: 1.0,
        };
        let window = Size {
            width: 820.0,
            height: 640.0,
        };
        assert_eq!(window_position(small, window), Point { x: -800.0, y: 0.0 });
    }

    #[test]
    fn the_pointer_is_turned_into_points_by_the_main_displays_factor() {
        assert_eq!(
            pointer_in_points(-1600.0, 400.0, 2.0),
            Point {
                x: -800.0,
                y: 200.0
            }
        );
        assert_eq!(
            pointer_in_points(10.0, 20.0, 0.0),
            Point { x: 10.0, y: 20.0 }
        );
    }
}
