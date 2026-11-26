use crate::pattern_rendering::RenderedPiece;
use crate::pattern_signature::LevelRange;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacedPiece {
    pub anchor: PieceAnchor,
    pub piece: RenderedPiece,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieceAnchor {
    Floating,
    FromStart(usize),
    BeforeEnd(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    ConflictingOffsets,
    EndOffsetShorterThanPattern,
    FileSizeUnreachable,
}

pub struct LayoutFrame<'frame> {
    pub prefix: &'frame [u8],
    pub suffix: &'frame [u8],
    pub filler: u8,
    pub floating_start: usize,
    pub smallest_length: usize,
    pub file_size: Option<LevelRange>,
}

pub fn lay_out(pieces: &[PlacedPiece], frame: &LayoutFrame<'_>) -> Result<Vec<u8>, LayoutError> {
    let mut canvas = Canvas::default();
    canvas.write(0, frame.prefix)?;
    for placed in pieces {
        if let PieceAnchor::FromStart(distance) = placed.anchor {
            canvas.write_piece_at(distance, &placed.piece)?;
        }
    }
    let mut floating_start = canvas.len().max(frame.floating_start);
    for placed in pieces
        .iter()
        .filter(|placed| placed.anchor == PieceAnchor::Floating)
    {
        if floating_start > 0 {
            floating_start = floating_start.saturating_add(1);
        }
        let core_start =
            floating_start.saturating_add(usize::from(placed.piece.leading_context.is_some()));
        canvas.write_piece_at(core_start, &placed.piece)?;
        floating_start = canvas.len();
    }
    let content_end = canvas.len();
    canvas.write(content_end, frame.suffix)?;
    let content_end = canvas.len();
    let total = total_length(pieces, content_end, frame)?;
    for placed in pieces {
        if let PieceAnchor::BeforeEnd(distance) = placed.anchor {
            let core_length = placed.piece.core.len();
            if core_length > distance {
                return Err(LayoutError::EndOffsetShorterThanPattern);
            }
            let start = total
                .checked_sub(distance)
                .ok_or(LayoutError::EndOffsetShorterThanPattern)?;
            let mut piece = placed.piece.clone();
            if start.saturating_add(core_length) == total {
                piece.trailing_context = None;
            }
            canvas.write_piece_at(start, &piece)?;
        }
    }
    canvas.finish(total, frame.filler)
}

fn total_length(
    pieces: &[PlacedPiece],
    content_end: usize,
    frame: &LayoutFrame<'_>,
) -> Result<usize, LayoutError> {
    let room_after_content = |placed: &PlacedPiece| match placed.anchor {
        PieceAnchor::BeforeEnd(distance) => {
            Some(distance.saturating_add(usize::from(placed.piece.leading_context.is_some())))
        }
        PieceAnchor::Floating | PieceAnchor::FromStart(_) => None,
    };
    let end_section = pieces.iter().filter_map(room_after_content).max();
    let separator = usize::from(end_section.is_some() && content_end > 0);
    let mut total = content_end
        .saturating_add(separator)
        .saturating_add(end_section.unwrap_or(0))
        .max(frame.smallest_length);
    if let Some(size) = frame.file_size {
        if let Some(minimum) = size.minimum {
            total = total.max(usize::try_from(minimum).unwrap_or(usize::MAX));
        }
        if size
            .maximum
            .is_some_and(|maximum| u64::try_from(total).unwrap_or(u64::MAX) > maximum)
        {
            return Err(LayoutError::FileSizeUnreachable);
        }
    }
    Ok(total)
}

#[derive(Default)]
struct Canvas {
    cells: Vec<Option<u8>>,
}

impl Canvas {
    fn len(&self) -> usize {
        self.cells.len()
    }

    fn write_piece_at(
        &mut self,
        core_start: usize,
        piece: &RenderedPiece,
    ) -> Result<(), LayoutError> {
        if let Some(context) = piece.leading_context
            && let Some(before) = core_start.checked_sub(1)
        {
            self.write(before, &[context])?;
        }
        self.write(core_start, &piece.core)?;
        if let Some(context) = piece.trailing_context {
            self.write(core_start.saturating_add(piece.core.len()), &[context])?;
        }
        Ok(())
    }

    fn write(&mut self, start: usize, bytes: &[u8]) -> Result<(), LayoutError> {
        let end = start.saturating_add(bytes.len());
        if self.cells.len() < end {
            self.cells.resize(end, None);
        }
        let cells = self
            .cells
            .get_mut(start..end)
            .ok_or(LayoutError::ConflictingOffsets)?;
        for (cell, byte) in cells.iter_mut().zip(bytes) {
            match cell {
                Some(existing) if existing != byte => return Err(LayoutError::ConflictingOffsets),
                _ => *cell = Some(*byte),
            }
        }
        Ok(())
    }

    fn finish(self, total: usize, filler: u8) -> Result<Vec<u8>, LayoutError> {
        if self.cells.len() > total {
            return Err(LayoutError::EndOffsetShorterThanPattern);
        }
        let mut bytes: Vec<u8> = self
            .cells
            .into_iter()
            .map(|cell| cell.unwrap_or(filler))
            .collect();
        bytes.resize(total, filler);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(anchor: PieceAnchor, core: &[u8]) -> PlacedPiece {
        PlacedPiece {
            anchor,
            piece: RenderedPiece {
                leading_context: None,
                core: core.to_vec(),
                trailing_context: None,
            },
        }
    }

    fn frame() -> LayoutFrame<'static> {
        LayoutFrame {
            prefix: b"",
            suffix: b"",
            filler: b'.',
            floating_start: 0,
            smallest_length: 6,
            file_size: None,
        }
    }

    #[test]
    fn fixed_pieces_sit_at_their_offset_and_floating_pieces_follow_with_a_separator() {
        let pieces = [
            piece(PieceAnchor::Floating, b"FL"),
            piece(PieceAnchor::FromStart(2), b"AB"),
        ];
        assert_eq!(lay_out(&pieces, &frame()).unwrap(), b"..AB.FL".to_vec());
    }

    #[test]
    fn end_pieces_sit_their_distance_before_the_end() {
        let pieces = [
            piece(PieceAnchor::Floating, b"FL"),
            piece(PieceAnchor::BeforeEnd(4), b"EN"),
        ];
        assert_eq!(lay_out(&pieces, &frame()).unwrap(), b"FL.EN..".to_vec());
    }

    #[test]
    fn short_inputs_are_padded_to_the_smallest_scanned_length() {
        assert_eq!(
            lay_out(&[piece(PieceAnchor::Floating, b"AB")], &frame()).unwrap(),
            b"AB....".to_vec()
        );
    }

    #[test]
    fn contexts_surround_the_core() {
        let mut placed = piece(PieceAnchor::FromStart(3), b"AB");
        placed.piece.leading_context = Some(b' ');
        placed.piece.trailing_context = Some(b'\n');
        assert_eq!(lay_out(&[placed], &frame()).unwrap(), b".. AB\n".to_vec());
    }

    #[test]
    fn impossible_layouts_are_errors() {
        assert_eq!(
            lay_out(
                &[
                    piece(PieceAnchor::FromStart(0), b"AB"),
                    piece(PieceAnchor::FromStart(1), b"CD")
                ],
                &frame()
            ),
            Err(LayoutError::ConflictingOffsets)
        );
        assert_eq!(
            lay_out(&[piece(PieceAnchor::BeforeEnd(1), b"AB")], &frame()),
            Err(LayoutError::EndOffsetShorterThanPattern)
        );
        let limited = LayoutFrame {
            file_size: Some(LevelRange {
                minimum: Some(0),
                maximum: Some(4),
            }),
            ..frame()
        };
        assert_eq!(
            lay_out(&[piece(PieceAnchor::Floating, b"AB")], &limited),
            Err(LayoutError::FileSizeUnreachable)
        );
    }
}
