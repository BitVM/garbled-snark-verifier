use rand::Rng;

use super::{
    Error, FinalizedCircuit,
    errors::CircuitError,
    evaluation::EvaluatedCircuit,
    structure::{Circuit, GateSource, VecGate},
};
use crate::{
    CircuitContext, Delta, GarbledWire, GarbledWires, S, WireId, core::gate::garbling::Blake3Hasher,
};

type DefaultHasher = Blake3Hasher;

#[derive(Debug)]
pub struct GarbledCircuit<G: GateSource = VecGate> {
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
        let delta = Delta::generate(rng);

        let mut wires = GarbledWires::new(self.num_wire);
        let mut issue_fn = || GarbledWire::random(rng, &delta);

        [
            <Self as CircuitContext>::FALSE_WIRE,
            <Self as CircuitContext>::TRUE_WIRE,
        ]
        .iter()
        .chain(self.input_wires.iter())
        .for_each(|wire_id| {
            wires.get_or_init(*wire_id, &mut issue_fn).unwrap();
        });

        

        let garbled_table = self
            .gates
            .iter()
            .enumerate()
            .filter_map(|(i, g)| {
                
                match g.garble::<H>(i, &mut wires, &delta, rng) {
                    Ok(Some(row)) => {
                        Some(Ok(row))
                    }
                    Ok(None) => {
                        None
                    }
                    Err(err) => {
                        log::error!("garble error: {err:?}");
                        Some(Err(err))
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        
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
        let mut evaluated = vec![Option::<crate::EvaluatedWire>::None; self.structure.num_wire];

        [Circuit::<G>::FALSE_WIRE, Circuit::<G>::TRUE_WIRE]
            .iter()
            .chain(self.structure.input_wires.iter())
            .copied()
            .try_for_each(|wire_id| {
                let value = match wire_id {
                    Circuit::<G>::TRUE_WIRE => true,
                    Circuit::<G>::FALSE_WIRE => false,
                    w => (get_input)(w).ok_or(Error::LostInput(wire_id))?,
                };
                let wire = self.wires.get(wire_id)?;
                let active_label = wire.select(value);

                

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
        let input_wires = [Circuit::<G>::TRUE_WIRE, Circuit::<G>::FALSE_WIRE]
            .iter()
            .chain(self.structure.input_wires.iter())
            .map(|&wire_id| {
                let value = match wire_id {
                    Circuit::<G>::TRUE_WIRE => true,
                    Circuit::<G>::FALSE_WIRE => false,
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
