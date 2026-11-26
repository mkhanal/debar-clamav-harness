use std::collections::BTreeMap;
use std::io::{self, Write};

use harness_report::Sha256;

use crate::difference::{Difference, short_hash};
use crate::run::Outcome;

pub fn print_outcome(outcome: &Outcome, output: &mut impl Write) -> io::Result<()> {
    let names: BTreeMap<Sha256, &str> = outcome
        .compared
        .iter()
        .map(|input| (input.input, input.name.as_str()))
        .collect();
    let judgement = &outcome.judgement;
    print_section(
        output,
        &names,
        "New differences. Each fails the run: fix Debar, or add its line to the known differences once the difference is accepted.",
        &judgement.new,
    )?;
    print_section(output, &names, "Known differences.", &judgement.known)?;
    print_section(
        output,
        &names,
        "Known differences that no longer occur. Remove their lines from the known differences.",
        &judgement.no_longer_occurring,
    )?;
    if !judgement.rules_not_used.is_empty() {
        writeln!(
            output,
            "Known-difference rules that covered nothing in this run. Remove them once no input needs them."
        )?;
        for rule in &judgement.rules_not_used {
            writeln!(output, "    {rule}")?;
        }
        writeln!(output)?;
    }
    if let Some(built) = &outcome.built_inputs {
        writeln!(
            output,
            "Built inputs: {} of {} detected by the reference under the signature each was built for; Debar detected {} of those, and {} others.",
            built.detected_by_reference,
            built.inputs,
            built.detected_by_both,
            built.detected_by_debar_only
        )?;
    }
    writeln!(
        output,
        "{} inputs compared: {} new, {} known, {} no longer occurring.",
        outcome.compared.len(),
        judgement.new.len(),
        judgement.known.len(),
        judgement.no_longer_occurring.len()
    )
}

fn print_section(
    output: &mut impl Write,
    names: &BTreeMap<Sha256, &str>,
    heading: &str,
    differences: &[Difference],
) -> io::Result<()> {
    if differences.is_empty() {
        return Ok(());
    }
    writeln!(output, "{heading}")?;
    for difference in differences {
        let name = names
            .get(&difference.input)
            .map_or_else(|| short_hash(&difference.input), |name| (*name).to_owned());
        writeln!(output, "  {name}: {}", difference.kind)?;
        writeln!(
            output,
            "    {}",
            serde_json::to_string(difference).map_err(io::Error::from)?
        )?;
    }
    writeln!(output)
}
