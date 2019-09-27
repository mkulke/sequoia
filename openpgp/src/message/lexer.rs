use std::fmt;

// The type of the parser's input.
//
// The parser iterators over tuples consisting of the token's starting
// position, the token itself, and the token's ending position.
pub(crate) type LexerItem<Tok, Loc, Error>
    = ::std::result::Result<(Loc, Tok, Loc), Error>;

/// The components of an OpenPGP Message.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Token {
    /// A Literal data packet.
    Literal,
    /// A Compressed Data packet.
    CompressedData,

    /// An SK-ESK packet.
    SKESK,
    /// An PK-ESK packet.
    PKESK,
    /// A SEIP packet.
    SEIP,
    /// An MDC packet.
    MDC,
    /// An AED packet.
    AED,

    /// A OnePassSig packet.
    OPS,
    /// A Signature packet.
    SIG,

    /// The end of a container (either a Compressed Data packet or a
    /// SEIP packet).
    Pop,

    /// A container's unparsed content.
    OpaqueContent,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("{:?}", self)[..])
    }
}

#[derive(Debug, Clone)]
pub enum LexicalError {
    // There are no lexing errors.
}

impl fmt::Display for LexicalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("{:?}", self)[..])
    }
}

pub(crate) struct Lexer<'input> {
    iter: Box<dyn Iterator<Item=(usize, &'input Token)> + 'input>,
}

impl<'input> Iterator for Lexer<'input> {
    type Item = LexerItem<Token, usize, LexicalError>;

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.iter.next().map(|(pos, tok)| (pos, tok.clone()));
        if let Some((pos, tok)) = n {
            Some(Ok((pos, tok, pos)))
        } else {
            None
        }
    }
}

impl<'input> Lexer<'input> {
    /// Uses a raw sequence of tokens as input to the parser.
    pub(crate) fn from_tokens(raw: &'input [Token]) -> Self {
        Lexer {
            iter: Box::new(raw.iter().enumerate())
        }
    }
}
