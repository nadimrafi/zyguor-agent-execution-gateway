#[derive(Debug, Clone, Copy)]
pub struct AddArguments {
    pub left: i32,
    pub right: i32,
}

#[derive(Debug, Clone, Copy)]
pub enum ExecutionRequest {
    Add(AddArguments),
}
