# Proof of Concept (PoC) for Controller and Node Agent

This repository contains the code for a Python-based controller and a Node.js agent, designed to demonstrate a basic implementation of a distributed system. The controller manages and communicates with multiple agents, which can be used to perform tasks such as data collection, processing, and reporting.

## Prerequisites

Before running the PoC, ensure you have the following installed:

- [Docker](https://www.docker.com/products/docker-desktop) (including Docker Compose)
- [Node.js](https://nodejs.org/) (for the agent)
- [Python](https://www.python.org/) (for the controller)

## Running the PoC with Docker Compose (Controller + Node Agent)

The repository includes a `docker-compose.yml` to run the Python controller and the Node.js agent together for local testing.

From a Windows `cmd.exe` terminal run:

```cmd
cd "c:\Users\bura\Desktop\proxy server"
docker compose up --build
```

This will:
- Build the controller image and launch it on port `9100`.
- Build the Node agent image and launch it, exposing the agent proxy on port `3128` and admin API on `3000`.

Check the controller logs for agent registration messages. Use `curl` to list agents:

```cmd
curl http://127.0.0.1:9100/agents
```

To stop the stack:

```cmd
docker compose down
```

## Controller

The controller is a Python application that manages the lifecycle of agent instances. It provides an API for registering agents, updating their status, and retrieving data collected by the agents.

### Running the Controller Manually

To run the controller manually (outside of Docker), execute the following commands:

```bash
# Create a Python virtual environment
python -m venv venv

# Activate the virtual environment
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

# Install the required packages
pip install -r requirements.txt

# Run the controller
python controller.py
```

The controller will start on `http://127.0.0.1:9100`.

### TLS for Admin API and Controller

TLS is optional and enabled by setting certificate paths via environment variables:

- Admin API: `ADMIN_TLS_CERT`, `ADMIN_TLS_KEY`
- Controller: `CONTROLLER_TLS_CERT`, `CONTROLLER_TLS_KEY`

When TLS is enabled, use `https://` for the controller endpoints and `wss://` for the WebSocket `/ws` route.

For a real (publicly trusted) certificate, the certificate hostname must match what clients connect to (public CAs
won't issue certs for `127.0.0.1`/`localhost`/Docker service names). In Docker Compose, `./certs` is mounted as
`/certs` inside the controller container.

## Agent

The agent is a Node.js application that performs tasks such as data collection and reporting. It registers itself with the controller and listens for commands.

### Running the Agent Manually

To run the agent manually (outside of Docker), execute the following commands:

```bash
# Install the required packages
npm install

# Run the agent
node agent.js
```

The agent will register with the controller and start listening on the configured ports.

## API Endpoints

### Controller API

- `POST /agents/register`: Register a new agent.
- `GET /agents`: List all registered agents.
- `GET /agents/{id}`: Get details of a specific agent.
- `PUT /agents/{id}/status`: Update the status of an agent.

### Agent API

- `GET /`: Health check endpoint.
- `POST /tasks`: Submit a new task for processing.
- `GET /results/{task_id}`: Retrieve the results of a completed task.

## Testing the PoC

To test the PoC, follow these steps:

1. Start the controller and agent using Docker Compose (see above instructions).
2. Register a new agent using the controller API:

   ```bash
   curl -X POST http://127.0.0.1:9100/agents/register -d '{"name": "Agent1"}' -H "Content-Type: application/json"
   ```

3. Submit a new task to the agent:

   ```bash
   curl -X POST http://127.0.0.1:3000/tasks -d '{"task": "collect_data"}' -H "Content-Type: application/json"
   ```

4. Check the status of the task:

   ```bash
   curl http://127.0.0.1:3000/results/{task_id}
   ```

5. Stop the Docker containers:

   ```bash
   docker compose down
   ```

## Troubleshooting

- Ensure that Docker is running and the required ports are not in use by other applications.
- Check the logs of the controller and agent for any error messages.
- Verify the network configuration in the `docker-compose.yml` file if the services cannot communicate with each other.

## Conclusion

This PoC demonstrates the basic functionality of a distributed system with a central controller and multiple agents. It can be extended with more advanced features such as authentication, encryption, and task scheduling.

## References

- [Docker Documentation](https://docs.docker.com/)
- [Node.js Documentation](https://nodejs.org/en/docs/)
- [Python Documentation](https://docs.python.org/3/)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
