use wasmtime::{Engine, Instance, Module, Store};

pub fn run_addition(left: i32, right: i32) -> Result<i32, String> {
    let engine = Engine::default();

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

    let instance = Instance::new(&mut store, &module, &[])
        .map_err(|error| format!("failed to instantiate Wasm module: {error}"))?;

    let add = instance
        .get_typed_func::<(i32, i32), i32>(&mut store, "add")
        .map_err(|error| format!("failed to load add function: {error}"))?;

    add.call(&mut store, (left, right))
        .map_err(|error| format!("Wasm execution failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::run_addition;

    #[test]
    fn executes_wasm_addition() -> Result<(), String> {
        let result = run_addition(2, 3)?;

        assert_eq!(result, 5);

        Ok(())
    }

    #[test]
    fn handles_negative_values() -> Result<(), String> {
        let result = run_addition(-2, 5)?;

        assert_eq!(result, 3);

        Ok(())
    }
}
