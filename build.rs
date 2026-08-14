fn main() {
    // 仅 Windows 目标嵌入图标（MSVC 工具链使用 rc.exe 编译资源）
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/app.ico");
        res.compile().expect("嵌入 exe 图标资源失败");
    }
}
