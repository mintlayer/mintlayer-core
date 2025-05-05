// Copyright (c) 2023 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub enum Container {
    PostgresFromDockerHub,
}

impl Container {
    pub fn container_name(&self) -> &str {
        match self {
            Container::PostgresFromDockerHub => "docker.io/library/postgres",
        }
    }
}

fn random_string(length: usize) -> String {
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn current_datetime_as_string() -> String {
    chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string()
}

pub struct Podman {
    name: String,
    env: Vec<(String, String)>,
    port_mappings: Vec<(Option<u16>, u16)>,
    container: Container,
    // `None` means that the container hasn't been created yet.
    is_running: Option<bool>,
}

impl Podman {
    #[must_use]
    pub fn new(name_prefix: &str, container: Container) -> Self {
        let name =
            [name_prefix.to_string(), current_datetime_as_string(), random_string(8)].join("-");

        Self {
            name,
            env: Vec::new(),
            port_mappings: Vec::new(),
            container,
            is_running: None,
        }
    }

    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    /// If `host_port` is `None`, the container port will be exposed on a random available host port.
    pub fn with_port_mapping(mut self, host_port: Option<u16>, container_port: u16) -> Self {
        self.port_mappings.push((host_port, container_port));
        self
    }

    pub fn run(&mut self) {
        let mut command = std::process::Command::new("podman");
        command.arg("run");
        command.arg("--detach");
        command.arg("--name");
        command.arg(&self.name);
        for (key, value) in &self.env {
            command.arg("-e");
            command.arg(format!("{}={}", key, value));
        }
        for (host_port, container_port) in &self.port_mappings {
            command.arg("-p");
            match host_port {
                Some(host_port) => command.arg(format!("{}:{}", host_port, container_port)),
                None => command.arg(format!("{}", container_port)),
            };
        }
        command.arg(self.container.container_name());
        Self::run_command(command);
        self.is_running = Some(true);
    }

    pub fn get_port_mapping(&self, container_port: u16) -> Option<u16> {
        let mut command = std::process::Command::new("podman");
        command.arg("port");
        command.arg(&self.name);
        command.arg(format!("{}", container_port));

        let output = Self::run_command(command);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let line = stdout.lines().next()?;
        let parts = line.split(':').collect::<Vec<&str>>();
        let port = parts
            .get(1)
            .expect("Failed to find host port with the format 0.0.0.0:2345")
            .parse::<u16>()
            .unwrap_or_else(|e| panic!("Failed to parse host port with the format to u16: {e}"));

        Some(port)
    }

    pub fn stop(&mut self) {
        let mut command = std::process::Command::new("podman");
        command.arg("stop");
        command.arg(&self.name);
        Self::run_command(command);
        self.is_running = Some(false);
    }

    pub fn restart(&mut self) {
        assert!(
            self.is_running == Some(false),
            "The container must have been created and stopped before it can be restarted"
        );
        let mut command = std::process::Command::new("podman");
        command.arg("start");
        command.arg(&self.name);
        Self::run_command(command);
        self.is_running = Some(true);
    }

    /// Uses the command `podman logs` to print the logs of the container.
    pub fn print_logs(&mut self) {
        let mut command = std::process::Command::new("podman");
        command.arg("logs");
        command.arg(&self.name);
        let output = Self::run_command(command);

        {
            let mut logs = String::new();
            logs.push_str("==================================================================\n");
            logs.push_str("==================================================================\n");
            logs.push_str("==================================================================\n");
            logs.push_str(&format!("Logs for container '{}' (stdout):\n", self.name));
            logs.push_str("==================================================================\n");
            logs.push_str(&String::from_utf8_lossy(&output.stdout));
            logs.push_str("==================================================================\n");
            logs.push_str("==================================================================\n");
            logs.push_str("==================================================================\n");
            logs.push_str(&format!("Logs for container '{}' (stderr):\n", self.name));
            logs.push_str("==================================================================\n");
            logs.push_str(&String::from_utf8_lossy(&output.stderr));
            logs.push_str("\n\n");
            logs.push_str("==================================================================\n");
            logs.push_str("==================================================================\n");
            logs.push_str("==================================================================\n");

            println!("{}", logs);
        }
    }

    fn run_command(mut command: std::process::Command) -> std::process::Output {
        let output = command.output().unwrap();
        logging::log::debug!(
            "Podman command args: {:?}",
            command.get_args().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ")
        );
        assert!(
            output.status.success(),
            "Failed to run podman command: {:?}\n{}",
            command,
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn remove_container(&mut self) {
        let mut command = std::process::Command::new("podman");
        command.arg("rm");
        command.arg(&self.name);
        Self::run_command(command);
    }

    fn destructor(&mut self) {
        if let Some(is_running) = self.is_running {
            self.print_logs();
            if is_running {
                self.stop();
            }
            self.remove_container();
        }
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for Podman {
    fn drop(&mut self) {
        self.destructor()
    }
}
