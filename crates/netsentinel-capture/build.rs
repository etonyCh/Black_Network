use anyhow::{anyhow, Context as _};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-env-changed=AYA_BUILD_SKIP");
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let out_path = std::path::Path::new(&out_dir).join("netsentinel-capture-ebpf");

    if std::env::var("AYA_BUILD_SKIP").is_ok() {
        if !out_path.exists() {
            std::fs::write(&out_path, [])?;
        }
        return Ok(());
    }

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "netsentinel-capture-ebpf")
        .ok_or_else(|| anyhow!("netsentinel-capture-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    if let Err(e) = aya_build::build_ebpf([ebpf_package], Toolchain::default()) {
        if !out_path.exists() {
            std::fs::write(&out_path, [])?;
        }
        return Err(e);
    }
    Ok(())
}
