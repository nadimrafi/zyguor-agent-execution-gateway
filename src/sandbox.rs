use wasmtime::{Config, Engine, Instance, Module, Store};

#[cfg(test)]
use wasmtime::{StoreLimits, StoreLimitsBuilder};
#[cfg(test)]
struct SandboxState {
    limits: StoreLimits,
}

const DEFAULT_FUEL: u64 = 10_000;

pub fn run_addition(left: i32, right: i32) -> Result<i32, String> {
    let mut config = Config::new();
    config.consume_fuel(true);

    let engine = Engine::new(&config)
        .map_err(|error| format!("failed to create Wasmtime engine: {error}"))?;

    let wasm = r#"
        (module
            (func (export "add") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.add
            )
        )
    "#;

    let module = Module::new(&engine, wasm)
        .map_err(|error| format!("failed to compile Wasm module: {error}"))?;

    let mut store = Store::new(&engine, ());

    store
        .set_fuel(DEFAULT_FUEL)
        .map_err(|error| format!("failed to configure Wasm fuel: {error}"))?;

    let instance = Instance::new(&mut store, &module, &[])
        .map_err(|error| format!("failed to instantiate Wasm module: {error}"))?;

    let add = instance
        .get_typed_func::<(i32, i32), i32>(&mut store, "add")
        .map_err(|error| format!("failed to load add function: {error}"))?;

    add.call(&mut store, (left, right))
        .map_err(|error| format!("Wasm execution failed: {error}"))
}

#[cfg(test)]
pub fn run_infinite_loop_with_fuel(fuel: u64) -> Result<(), String> {
    let mut config = Config::new();
    config.consume_fuel(true);

    let engine = Engine::new(&config)
        .map_err(|error| format!("failed to create Wasmtime engine: {error}"))?;

    let wasm = r#"
        (module
            (func (export "run")
                (loop
                    br 0
                )
            )
        )
    "#;

    let module = Module::new(&engine, wasm)
        .map_err(|error| format!("failed to compile Wasm module: {error}"))?;

    let mut store = Store::new(&engine, ());

    store
        .set_fuel(fuel)
        .map_err(|error| format!("failed to configure Wasm fuel: {error}"))?;

    let instance = Instance::new(&mut store, &module, &[])
        .map_err(|error| format!("failed to instantiate Wasm module: {error}"))?;

    let run = instance
        .get_typed_func::<(), ()>(&mut store, "run")
        .map_err(|error| format!("failed to load run function: {error}"))?;

    run.call(&mut store, ())
        .map_err(|error| format!("Wasm execution failed: {error}"))
}
#[cfg(test)]
pub fn run_memory_growth_with_limit(memory_limit_bytes: usize) -> Result<(), String> {
    let engine = Engine::default();

    let wasm = r#"
        (module
            (memory 1)
            (func (export "grow")
                i32.const 100
                memory.grow
                drop
            )
        )
    "#;

    let module = Module::new(&engine, wasm)
        .map_err(|error| format!("failed to compile Wasm module: {error}"))?;

    let limits = StoreLimitsBuilder::new()
        .memory_size(memory_limit_bytes)
        .trap_on_grow_failure(true)
        .build();

    let mut store = Store::new(&engine, SandboxState { limits });

    store.limiter(|state| &mut state.limits);

    let instance = Instance::new(&mut store, &module, &[])
        .map_err(|error| format!("failed to instantiate Wasm module: {error}"))?;

    let grow = instance
        .get_typed_func::<(), ()>(&mut store, "grow")
        .map_err(|error| format!("failed to load grow function: {error}"))?;

    grow.call(&mut store, ())
        .map_err(|error| format!("Wasm memory growth failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{run_addition, run_infinite_loop_with_fuel, run_memory_growth_with_limit};

    #[test]
    fn blocks_wasm_memory_growth_beyond_limit() {
        let result = run_memory_growth_with_limit(128 * 1024);

        assert!(result.is_err());
    }

    #[test]
    fn executes_wasm_addition() -> Result<(), String> {
        let result = run_addition(2, 3)?;

        assert_eq!(result, 5);

        Ok(())
    }

    #[test]
    fn stops_runaway_wasm_when_fuel_is_exhausted() {
        let result = run_infinite_loop_with_fuel(1_000);

        assert!(result.is_err());
    }

    #[test]
    fn handles_negative_values() -> Result<(), String> {
        let result = run_addition(-2, 5)?;

        assert_eq!(result, 3);

        Ok(())
    }
}
