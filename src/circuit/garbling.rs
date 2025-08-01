use rand::Rng;

use super::{
    Error, FinalizedCircuit, errors::CircuitError, evaluation::EvaluatedCircuit, structure::{Circuit, GateSource},
};
use crate::{Delta, Gate, GarbledWire, GarbledWires, S, WireId};
use crate::core::gate::garbling::Blake3Hasher;

type DefaultHasher = Blake3Hasher;

#[derive(Debug)]
pub struct GarbledCircuit<G: GateSource = Vec<Gate>> {
    pub structure: Circuit<G>,
    pub wires: GarbledWires,
    pub delta: Delta,
    pub garbled_table: Vec<S>,
}

impl<G: GateSource> Circuit<G> {
    pub fn garble(&self, rng: &mut impl Rng) -> Result<GarbledCircuit<G>, CircuitError> {
        self.garble_with::<DefaultHasher>(rng)
    }

    pub fn garble_with<H: crate::core::gate::garbling::GateHasher>(
        &self,
        rng: &mut impl Rng,
    ) -> Result<GarbledCircuit<G>, CircuitError> {
        log::debug!(
            "garble: start wires={} gates={}",
            self.num_wire,
            self.gates.len()
        );

        let delta = Delta::generate(rng);

        let mut wires = GarbledWires::new(self.num_wire);
        let mut issue_fn = || GarbledWire::random(rng, &delta);

        [
            self.get_false_wire_constant(),
            self.get_true_wire_constant(),
        ]
        .iter()
        .chain(self.input_wires.iter())
        .for_each(|wire_id| {
            wires.get_or_init(*wire_id, &mut issue_fn).unwrap();
        });

        log::debug!("garble: delta={delta:?}");

        let garbled_table = self
            .gates
            .iter()
            .enumerate()
            .filter_map(|(i, g)| {
                log::debug!(
                    "garble: gate[{}] {:?} {}+{}->{}",
                    i,
                    g.gate_type,
                    g.wire_a,
                    g.wire_b,
                    g.wire_c
                );
                match g.garble::<H>(i, &mut wires, &delta, rng) {
                    Ok(Some(row)) => {
                        log::debug!("garble: gate[{i}] table_entries={row:?}");
                        Some(Ok(row))
                    }
                    Ok(None) => {
                        log::debug!("garble: gate[{i}] free");
                        None
                    }
                    Err(err) => {
                        log::error!("garble: gate[{i}] error={err:?}");
                        Some(Err(err))
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        log::debug!("garble: complete table_size={}", garbled_table.len());
        Ok(GarbledCircuit {
            structure: self.clone(),
            wires,
            delta,
            garbled_table,
        })
    }
}

impl<G: GateSource> GarbledCircuit<G> {
    pub fn evaluate(
        &self,
        get_input: impl Fn(WireId) -> Option<bool>,
    ) -> Result<EvaluatedCircuit<G>, Error> {
        log::debug!(
            "evaluate: start wires={} gates={} table_entries={}",
            self.structure.num_wire,
            self.structure.gates.len(),
            self.garbled_table.len()
        );
        let mut evaluated = vec![Option::<crate::EvaluatedWire>::None; self.structure.num_wire];

        let true_wire = self.structure.get_true_wire_constant();
        let false_wire = self.structure.get_false_wire_constant();

        [true_wire, false_wire]
            .iter()
            .chain(self.structure.input_wires.iter())
            .copied()
            .try_for_each(|wire_id| {
                let value = match wire_id {
                    w if w.eq(&true_wire) => true,
                    w if w.eq(&false_wire) => false,
                    w => (get_input)(w).ok_or(Error::LostInput(wire_id))?,
                };
                let wire = self.wires.get(wire_id)?;
                let active_label = wire.select(value);

                log::debug!("evaluate: input {wire_id}={value} label={active_label:?}");

                evaluated[wire_id.0] = Some(crate::EvaluatedWire {
                    active_label,
                    value,
                });
                Result::<_, Error>::Ok(())
            })?;

        for gate in self.structure.gates.iter() {
            let a = evaluated
                .get(gate.wire_a.0)
                .and_then(|eg| eg.as_ref())
                .ok_or(Error::WrongGateOrder {
                    gate: gate.clone(),
                    wire_id: gate.wire_a,
                })?;
            let b = evaluated
                .get(gate.wire_b.0)
                .and_then(|eg| eg.as_ref())
                .ok_or(Error::WrongGateOrder {
                    gate: gate.clone(),
                    wire_id: gate.wire_b,
                })?;
            let c = self.wires.get(gate.wire_c).unwrap();

            evaluated[gate.wire_c.0] = Some(gate.evaluate(a, b, c));
        }

        Ok(EvaluatedCircuit {
            wires: evaluated.into_iter().map(Option::unwrap).collect(),
            structure: self.structure.clone(),
            garbled_table: self.garbled_table.clone(),
        })
    }

    pub fn finalize(
        &self,
        get_input: impl Fn(WireId) -> Option<bool>,
    ) -> Result<FinalizedCircuit<G>, Error> {
        let outputs = self
            .structure
            .simple_evaluate(&get_input)?
            .collect::<std::collections::HashMap<_, _>>();

        // Collect input wires with their garbled wire labels
        let input_wires = [
            self.structure.get_false_wire_constant(),
            self.structure.get_true_wire_constant(),
        ]
        .iter()
        .chain(self.structure.input_wires.iter())
        .map(|&wire_id| {
            let value = match wire_id {
                w if w == self.structure.get_true_wire_constant() => true,
                w if w == self.structure.get_false_wire_constant() => false,
                w => get_input(w).ok_or(Error::LostInput(wire_id))?,
            };
            let wire = self.wires.get(wire_id)?;
            let active_label = wire.select(value);

            Ok((
                wire_id,
                crate::EvaluatedWire {
                    active_label,
                    value,
                },
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;

        // Create output wires iterator with their garbled wire labels
        let output_wires = outputs.into_iter().map(|(wire_id, value)| {
            let wire = self.wires.get(wire_id).unwrap();
            let active_label = wire.select(value);
            crate::EvaluatedWire {
                active_label,
                value,
            }
        });

        Ok(FinalizedCircuit::new(
            self.structure.clone(),
            input_wires,
            output_wires,
            self.garbled_table.clone(),
        ))
    }
}
