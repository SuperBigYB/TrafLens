/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::error::Error;
use std::process::Command;

fn generate_protobuf() -> Result<(), Box<dyn Error>> {
    tonic_build::configure()
        .build_server(false)
        .out_dir("src/proto")
        .compile(
            &[
                "../../../message/metric.proto",
                "../../../message/flow_log.proto",
                "../../../message/stats.proto",
                "../../../message/k8s_event.proto",
            ],
            &["../../../message"],
        )?;
    tonic_build::configure()
        .build_server(true)
        .out_dir("src/proto")
        .compile(&["../../../message/agent.proto"], &["../../../message"])?;
    tonic_build::configure()
        .build_server(false)
        .out_dir("src/proto/integration")
        .compile(
            &["../../../message/opentelemetry/opentelemetry/proto/trace/v1/trace.proto"],
            &["../../../message/opentelemetry"],
        )?;

    // Format only generated outputs, and finish before rustc reads them.
    // `cargo fmt` formats the workspace even when rustfmt file arguments follow
    // `--`, which can modify unrelated checked-in source during a build.
    let mut generated = Vec::new();
    for directory in ["src/proto", "src/proto/integration"] {
        for entry in std::fs::read_dir(directory)? {
            let path = entry?.path();
            if path.extension().is_some_and(|extension| extension == "rs") {
                generated.push(path);
            }
        }
    }
    generated.sort();
    let rustfmt = std::env::var_os("RUSTFMT").unwrap_or_else(|| "rustfmt".into());
    let status = Command::new(rustfmt)
        .args(["--edition", "2021"])
        .args(generated)
        .status()?;
    if !status.success() {
        return Err("formatting generated protobuf output failed".into());
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    generate_protobuf()?;
    Ok(())
}
