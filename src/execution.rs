#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestArguments {
    pub method: HttpMethod,
    pub url: String,
    pub body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionRequest {
    Add(AddArguments),
    ReadFile(ReadFileArguments),
    WriteFile(WriteFileArguments),
    GitStatus,
    RunCargoTest,
    HttpRequest(HttpRequestArguments),
}
