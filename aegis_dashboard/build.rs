// build.rs — Link aegis_dashboard against C++ IPC Bridge shared library
// On Windows: aegis_ipc.dll, On Linux: libaegis_ipc.so

fn main() {
    // Try multiple library search paths
    let search_paths = [
        "../build/Release",
        "../build",
        "../build_cmake",
        "../bridge",
    ];

    for path in &search_paths {
        println!("cargo:rustc-link-search=native={}", path);
    }

    // Link the C++ IPC Bridge shared library
    println!("cargo:rustc-link-lib=dylib=aegis_ipc");
}
