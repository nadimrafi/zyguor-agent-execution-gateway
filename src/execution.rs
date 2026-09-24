#[derive(Debug, Clone, Copy)]
pub struct AddArguments {
    pub left: i32,
    pub right: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFileArguments {
    pub path: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteFileArguments {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub enum ExecutionRequest {
    Add(AddArguments),
    ReadFile(ReadFileArguments),
    WriteFile(WriteFileArguments),
}
