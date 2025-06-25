use anyhow::Result;

use ruff_macros::{ViolationMetadata, derive_message_formats};
use ruff_python_ast::{self as ast, Expr, Operator};
use ruff_python_semantic::{Modules, SemanticModel};
use ruff_text_size::Ranged;

use crate::Violation;
use crate::checkers::ast::Checker;

/// ## What it does
/// Checks for files with overly permissive permissions.
///
/// ## Why is this bad?
/// Overly permissive file permissions may allow unintended access and
/// arbitrary code execution.
///
/// ## Example
/// ```python
/// import os
///
/// os.chmod("/etc/secrets.txt", 0o666)  # Bad: world-writable
/// os.chmod("/tmp/file", 0o777)         # Bad: world-writable and executable
/// os.chmod("/app/script", 0o4755)      # Bad: setuid
/// ```
///
/// Use instead:
/// ```python
/// import os
///
/// os.chmod("/etc/secrets.txt", 0o600)  # Good: owner only
/// os.chmod("/tmp/file", 0o644)         # Good: owner write, others read
/// ```
///
/// ## References
/// - [Python documentation: `os.chmod`](https://docs.python.org/3/library/os.html#os.chmod)
/// - [Python documentation: `stat`](https://docs.python.org/3/library/stat.html)
/// - [Common Weakness Enumeration: CWE-732](https://cwe.mitre.org/data/definitions/732.html)
#[derive(ViolationMetadata)]
pub(crate) struct BadFilePermissions {
    mask: u16,
    issue: &'static str,
}

impl Violation for BadFilePermissions {
    #[derive_message_formats]
    fn message(&self) -> String {
        format!(
            "`os.chmod` setting {} permissions `{:#o}`",
            self.issue, self.mask
        )
    }
}

/// S103
pub(crate) fn bad_file_permissions(checker: &Checker, call: &ast::ExprCall) {
    if !checker.semantic().seen_module(Modules::OS) {
        return;
    }

    let Some(qualified_name) = checker.semantic().resolve_qualified_name(&call.func) else {
        return;
    };

    if !matches!(qualified_name.segments(), ["os", "chmod"]) {
        return;
    }

    let Some(mode_arg) = call.arguments.find_argument_value("mode", 1) else {
        return;
    };

    match parse_mask(mode_arg, checker.semantic()) {
        Ok(Some(mask)) => {
            if let Some(issue) = check_dangerous_permissions(mask) {
                checker.report_diagnostic(BadFilePermissions { mask, issue }, mode_arg.range());
            }
        }
        Err(_) => {
            checker.report_diagnostic(
                BadFilePermissions {
                    mask: 0,
                    issue: "invalid",
                },
                mode_arg.range(),
            );
        }
        Ok(None) => {} // Dynamic value, can't analyze
    }
}

// Permission bits
const WRITE_OTHER: u16 = 0o002;
const EXECUTE_OTHER: u16 = 0o001;
const EXECUTE_GROUP: u16 = 0o010;
const SETUID: u16 = 0o4000;
const SETGID: u16 = 0o2000;

fn check_dangerous_permissions(mask: u16) -> Option<&'static str> {
    if mask & (SETUID | SETGID) != 0 {
        Some("setuid/setgid")
    } else if mask & WRITE_OTHER != 0 {
        Some("world-writable")
    } else if mask & EXECUTE_OTHER != 0 {
        Some("world-executable")
    } else if mask & EXECUTE_GROUP != 0 && mask & 0o070 == 0o070 {
        Some("overly permissive group")
    } else {
        None
    }
}
#[allow(clippy::match_wildcard_for_single_variants)]
fn parse_mask(expr: &Expr, semantic: &SemanticModel) -> Result<Option<u16>> {
    match expr {
        Expr::NumberLiteral(ast::ExprNumberLiteral {
            value: ast::Number::Int(int),
            ..
        }) => {
            // Convert to u64 first, then mask to valid permission bits
            if let Some(val) = int.as_u64() {
                Ok(Some((val & 0o7777) as u16))
            } else {
                Err(anyhow::anyhow!("invalid permission mask"))
            }
        }

        Expr::Attribute(_) => Ok(resolve_stat_constant(expr, semantic)),

        Expr::BinOp(ast::ExprBinOp {
            left, op, right, ..
        }) => {
            let (Some(l), Some(r)) = (parse_mask(left, semantic)?, parse_mask(right, semantic)?)
            else {
                return Ok(None);
            };

            Ok(Some(match op {
                Operator::BitAnd => l & r,
                Operator::BitOr => l | r,
                Operator::BitXor => l ^ r,
                Operator::LShift if r <= 15 => l.checked_shl(u32::from(r)).unwrap_or(0),
                Operator::RShift => l >> r.min(15),
                _ => return Ok(None),
            }))
        }

        Expr::UnaryOp(ast::ExprUnaryOp { op, operand, .. }) => match op {
            ast::UnaryOp::Invert => parse_mask(operand, semantic).map(|o| o.map(|v| !v)),
            ast::UnaryOp::UAdd => parse_mask(operand, semantic),
            ast::UnaryOp::USub => Err(anyhow::anyhow!("negative permissions")),
            _ => Ok(None),
        },

        _ => Ok(None),
    }
}

fn resolve_stat_constant(expr: &Expr, semantic: &SemanticModel) -> Option<u16> {
    let qualified_name = semantic.resolve_qualified_name(expr)?;

    match qualified_name.segments() {
        ["stat", name] => STAT_CONSTANTS
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, value)| *value),
        _ => None,
    }
}

// Common stat constants as (name, value) pairs
const STAT_CONSTANTS: &[(&str, u16)] = &[
    ("S_IXOTH", 0o001),
    ("S_IWOTH", 0o002),
    ("S_IROTH", 0o004),
    ("S_IRWXO", 0o007),
    ("S_IXGRP", 0o010),
    ("S_IWGRP", 0o020),
    ("S_IRGRP", 0o040),
    ("S_IRWXG", 0o070),
    ("S_IXUSR", 0o100),
    ("S_IWUSR", 0o200),
    ("S_IRUSR", 0o400),
    ("S_IRWXU", 0o700),
    ("S_ISVTX", 0o1000),
    ("S_ISGID", 0o2000),
    ("S_ISUID", 0o4000),
    ("S_IREAD", 0o400),
    ("S_IWRITE", 0o200),
    ("S_IEXEC", 0o100),
];
