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
    stopped: bool,
}

impl Podman {
    #[must_use]
    pub fn new(name_prefix: &str, container: Container) -> Self {
        let name =
            [name_prefix.to_string(), current_datetime_as_string(), random_string(8)].join("_");

        Self {
            name,
            env: Vec::new(),
            port_mappings: Vec::new(),
            container,
            stopped: false,
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

    pub fn run(&self) {
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
        println!(
            "Podman command args: {:?}",
            command.get_args().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ")
        );
        let output = command.output().unwrap();
        if !output.status.success() {
            panic!(
                "Failed to run podman command: {:?}\n{}",
                command,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    pub fn get_port_mapping(&self, container_port: u16) -> Option<u16> {
        let mut command = std::process::Command::new("podman");
        command.arg("port");
        command.arg(&self.name);
        command.arg(format!("{}", container_port));

        let output = command.output().unwrap();
        if !output.status.success() {
            panic!(
                "Failed to run podman command: {:?}\n{}",
                command,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let stdout = String::from_utf8(output.stdout).unwrap();
        let line = match stdout.lines().next() {
            Some(line) => line,
            None => return None,
        };
        let parts = line.split(':').collect::<Vec<&str>>();
        let port = parts
            .get(1)
            .expect("Failed to find host port with the format 0.0.0.0:2345")
            .parse::<u16>()
            .unwrap_or_else(|e| panic!("Failed to parse host port with the format to u16: {e}"));

        Some(port)
    }

    pub fn stop(&self) {
        // TODO(PR): remove the container, not just stop it
        let mut command = std::process::Command::new("podman");
        command.arg("stop");
        command.arg(&self.name);
        let output = command.output().unwrap();
        if !output.status.success() {
            panic!(
                "Failed to run podman command: {:?}\n{}",
                command,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for Podman {
    fn drop(&mut self) {
        if !self.stopped {
            self.stop();
        }
    }
}

// TODO(PR): remove the prints
