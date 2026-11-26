use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetType {
    Any,
    PortableExecutable,
    Ole2,
    Html,
    Mail,
    Graphics,
    Elf,
    Ascii,
    Unassigned,
    MachO,
    Pdf,
    Flash,
    Java,
    Internal,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputRoute {
    RawBytes,
    NormalisedText,
    NormalisedHtml,
    MailMessage,
    Container(ContainerKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContainerKind {
    PortableExecutable,
    Ole2,
    Graphics,
    Elf,
    MachO,
    Pdf,
    Flash,
    Java,
    ScannerMetadata,
    BinaryDataObject,
    UnassignedTarget,
}

impl fmt::Display for ContainerKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PortableExecutable => "PE",
            Self::Ole2 => "OLE2",
            Self::Graphics => "graphics",
            Self::Elf => "ELF",
            Self::MachO => "Mach-O",
            Self::Pdf => "PDF",
            Self::Flash => "Flash",
            Self::Java => "Java",
            Self::ScannerMetadata => "scanner metadata",
            Self::BinaryDataObject => "binary-data object",
            Self::UnassignedTarget => "unassigned target",
        })
    }
}

impl TargetType {
    #[must_use]
    pub fn from_code(code: u32) -> Option<Self> {
        let target = match code {
            0 => Self::Any,
            1 => Self::PortableExecutable,
            2 => Self::Ole2,
            3 => Self::Html,
            4 => Self::Mail,
            5 => Self::Graphics,
            6 => Self::Elf,
            7 => Self::Ascii,
            8 => Self::Unassigned,
            9 => Self::MachO,
            10 => Self::Pdf,
            11 => Self::Flash,
            12 => Self::Java,
            13 => Self::Internal,
            14 => Self::Other,
            _ => return None,
        };
        Some(target)
    }

    #[must_use]
    pub fn route(self) -> InputRoute {
        match self {
            Self::Any => InputRoute::RawBytes,
            Self::Ascii => InputRoute::NormalisedText,
            Self::Html => InputRoute::NormalisedHtml,
            Self::Mail => InputRoute::MailMessage,
            Self::PortableExecutable => InputRoute::Container(ContainerKind::PortableExecutable),
            Self::Ole2 => InputRoute::Container(ContainerKind::Ole2),
            Self::Graphics => InputRoute::Container(ContainerKind::Graphics),
            Self::Elf => InputRoute::Container(ContainerKind::Elf),
            Self::MachO => InputRoute::Container(ContainerKind::MachO),
            Self::Pdf => InputRoute::Container(ContainerKind::Pdf),
            Self::Flash => InputRoute::Container(ContainerKind::Flash),
            Self::Java => InputRoute::Container(ContainerKind::Java),
            Self::Internal => InputRoute::Container(ContainerKind::ScannerMetadata),
            Self::Other => InputRoute::Container(ContainerKind::BinaryDataObject),
            Self::Unassigned => InputRoute::Container(ContainerKind::UnassignedTarget),
        }
    }

    #[must_use]
    pub fn parses_executable_headers(self) -> bool {
        matches!(self, Self::PortableExecutable | Self::Elf | Self::MachO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_targets_zero_to_fourteen_exist() {
        assert_eq!(TargetType::from_code(0), Some(TargetType::Any));
        assert_eq!(TargetType::from_code(14), Some(TargetType::Other));
        assert_eq!(TargetType::from_code(15), None);
    }

    #[test]
    fn executable_targets_need_their_container() {
        assert_eq!(
            TargetType::PortableExecutable.route(),
            InputRoute::Container(ContainerKind::PortableExecutable)
        );
        assert_eq!(TargetType::Any.route(), InputRoute::RawBytes);
        assert_eq!(TargetType::Ascii.route(), InputRoute::NormalisedText);
    }
}
