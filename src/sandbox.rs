use std::{sync::mpsc, thread, time::Duration};

use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

struct SandboxState {
    limits: StoreLimits,
}

#[derive(Debug, Clone, Copy)]
pub struct SandboxConfig {
    pub fuel_limit: u64,
    pub memory_limit_bytes: usize,
    pub timeout: Duration,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            fuel_limit: 10_000,
            memory_limit_bytes: 2 * 1024 * 1024,
            timeout: Duration::from_millis(250),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AddArguments {
    pub left: i32,
    pub right: i32,
}

#[derive(Debug, Clone, Copy)]
pub enum ExecutionRequest {
    Add(AddArguments),
}

pub struct SandboxExecutor {
    config: SandboxConfig,
}

impl SandboxExecutor {
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }
    pub fn execute(&self, request: ExecutionRequest) -> Result<i32, String> {
        match request {
            ExecutionRequest::Add(arguments) => self.run_addition(arguments.left, arguments.right),
        }
    }

    #[cfg(test)]
    pub fn config(&self) -> SandboxConfig {
        self.config
    }

    pub fn run_addition(&self, left: i32, right: i32) -> Result<i32, String> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);

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

        let limits = StoreLimitsBuilder::new()
            .memory_size(self.config.memory_limit_bytes)
            .trap_on_grow_failure(true)
            .build();

        let mut store = Store::new(&engine, SandboxState { limits });

        store.limiter(|state| &mut state.limits);

        store
            .set_fuel(self.config.fuel_limit)
            .map_err(|error| format!("failed to configure Wasm fuel: {error}"))?;

        store.set_epoch_deadline(1);
        store.epoch_deadline_trap();

        let instance = Instance::new(&mut store, &module, &[])
            .map_err(|error| format!("failed to instantiate Wasm module: {error}"))?;

        let add = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "add")
            .map_err(|error| format!("failed to load add function: {error}"))?;

        let timeout = self.config.timeout;
        let timer_engine = engine.clone();

        let (cancel_sender, cancel_receiver) = mpsc::channel::<()>();

        let timer = thread::spawn(move || {
            if cancel_receiver.recv_timeout(timeout).is_err() {
                timer_engine.increment_epoch();
            }
        });

        let execution_result = add.call(&mut store, (left, right));

        let _ = cancel_sender.send(());

        timer
            .join()
            .map_err(|_| "sandbox timeout thread failed".to_owned())?;

        execution_result.map_err(|error| format!("Wasm execution failed: {error}"))
    }
}
#[cfg(test)]
const DEFAULT_FUEL: u64 = 10_000;

#[cfg(test)]
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
pub fn run_infinite_loop_with_epoch_timeout(timeout: Duration) -> Result<(), String> {
    let mut config = Config::new();
    config.epoch_interruption(true);

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

    store.set_epoch_deadline(1);
    store.epoch_deadline_trap();

    let instance = Instance::new(&mut store, &module, &[])
        .map_err(|error| format!("failed to instantiate Wasm module: {error}"))?;

    let run = instance
        .get_typed_func::<(), ()>(&mut store, "run")
        .map_err(|error| format!("failed to load run function: {error}"))?;

    let timer_engine = engine.clone();

    let timer = thread::spawn(move || {
        thread::sleep(timeout);
        timer_engine.increment_epoch();
    });

    let execution_result = run.call(&mut store, ());

    timer
        .join()
        .map_err(|_| "epoch timer thread failed".to_owned())?;

    execution_result.map_err(|error| format!("Wasm execution interrupted: {error}"))
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

    use super::{
        AddArguments, ExecutionRequest, SandboxConfig, SandboxExecutor, run_addition,
        run_infinite_loop_with_epoch_timeout, run_infinite_loop_with_fuel,
        run_memory_growth_with_limit,
    };

    use std::time::Duration;
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
    fn interrupts_runaway_wasm_after_epoch_deadline() {
        let result = run_infinite_loop_with_epoch_timeout(Duration::from_millis(50));

        assert!(result.is_err());
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
    #[test]
    fn sandbox_config_has_safe_defaults() {
        let config = SandboxConfig::default();

        assert_eq!(config.fuel_limit, 10_000);
        assert_eq!(config.memory_limit_bytes, 2 * 1024 * 1024);
        assert_eq!(config.timeout, Duration::from_millis(250));
    }

    #[test]
    fn sandbox_executor_keeps_configuration() {
        let config = SandboxConfig {
            fuel_limit: 5_000,
            memory_limit_bytes: 1024 * 1024,
            timeout: Duration::from_millis(100),
        };

        let executor = SandboxExecutor::new(config);

        assert_eq!(executor.config().fuel_limit, 5_000);
        assert_eq!(executor.config().memory_limit_bytes, 1024 * 1024);
        assert_eq!(executor.config().timeout, Duration::from_millis(100));
    }
    #[test]
    fn executor_handles_add_request() -> Result<(), String> {
        let executor = SandboxExecutor::new(SandboxConfig::default());

        let result = executor.execute(ExecutionRequest::Add(AddArguments { left: 7, right: 5 }))?;

        assert_eq!(result, 12);

        Ok(())
    }
    #[test]
    fn execution_request_preserves_values() {
        let request = ExecutionRequest::Add(AddArguments { left: -4, right: 9 });

        match request {
            ExecutionRequest::Add(arguments) => {
                assert_eq!(arguments.left, -4);
                assert_eq!(arguments.right, 9);
            }
        }
    }
}
