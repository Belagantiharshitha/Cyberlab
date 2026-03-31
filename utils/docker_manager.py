import docker
from docker.errors import DockerException, APIError
import time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

LAB_CONFIGS = {
    "juice-shop": {
        "name": "OWASP Juice Shop",
        "description": "Modern web application packed with severe security flaws.",
        "image": "bkimminich/juice-shop",
        "internal_port": "3000/tcp",
        "entry_path": "",
        "mem_limit": "1g",
        "needs_volume": True,
        "volume_path": "/juice-shop/data"
    },
    "dvwa": {
        "name": "DVWA",
        "description": "Classic PHP/MySQL vulnerable utility for foundational SQLi & XSS.",
        "image": "vulnerables/web-dvwa",
        "internal_port": "80/tcp",
        "entry_path": "",
        "mem_limit": "512m",
        "needs_volume": False,
        "volume_path": ""
    },
    "bwapp": {
        "name": "bWAPP (Buggy Web App)",
        "description": "Deliberately insecure application featuring 100+ vulnerabilities.",
        "image": "raesene/bwapp",
        "internal_port": "80/tcp",
        "entry_path": "",
        "mem_limit": "512m",
        "needs_volume": False,
        "volume_path": ""
    },
    "webgoat": {
        "name": "OWASP WebGoat",
        "description": "Insecure enterprise Java EE application maintained by OWASP.",
        "image": "webgoat/webgoat-8.0",
        "internal_port": "8080/tcp",
        "entry_path": "/WebGoat",
        "mem_limit": "1g",
        "needs_volume": False,
        "volume_path": ""
    },
    "mutillidae": {
        "name": "Mutillidae II",
        "description": "OWASP Mutillidae vulnerable web app.",
        "image": "citizenstig/nowasp",
        "internal_port": "80/tcp",
        "entry_path": "",
        "mem_limit": "512m",
        "needs_volume": False,
        "volume_path": ""
    },
    "railsgoat": {
        "name": "RailsGoat",
        "description": "Vulnerable Ruby on Rails app for secure coding training.",
        "image": "owasp/railsgoat",
        "internal_port": "3000/tcp",
        "entry_path": "",
        "mem_limit": "768m",
        "needs_volume": False,
        "volume_path": "",
        "command": ["bash", "-lc", "bundle exec rails db:migrate && bundle exec rails db:seed && bundle exec rails server -b 0.0.0.0 -p 3000"]
    },
    "dvga": {
        "name": "DVGA",
        "description": "Damn Vulnerable GraphQL Application.",
        "image": "dolevf/dvga",
        "internal_port": "5013/tcp",
        "entry_path": "",
        "mem_limit": "512m",
        "needs_volume": False,
        "volume_path": "",
        "environment": {
            "WEB_HOST": "0.0.0.0"
        }
    },
    "vampi": {
        "name": "VAmPI",
        "description": "Vulnerable API intentionally designed for API attacks.",
        "image": "erev0s/vampi",
        "internal_port": "5000/tcp",
        "entry_path": "",
        "mem_limit": "512m",
        "needs_volume": False,
        "volume_path": ""
    },
    "juice-shop-ctf": {
        "name": "Juice Shop CTF",
        "description": "CTF-oriented Juice Shop training profile.",
        "image": "bkimminich/juice-shop",
        "internal_port": "3000/tcp",
        "entry_path": "",
        "mem_limit": "1g",
        "needs_volume": True,
        "volume_path": "/juice-shop/data"
    },
    "kubehunter": {
        "name": "KubeHunter",
        "description": "Kubernetes attack surface hunting toolkit container.",
        "image": "aquasec/kube-hunter",
        "internal_port": "8080/tcp",
        "access_mode": "cli",
        "entry_path": "",
        "mem_limit": "512m",
        "needs_volume": False,
        "volume_path": "",
        "command": ["tail", "-f", "/dev/null"],
        "override_entrypoint": True,
        "interactive": True
    },
    "redis": {
        "name": "Redis",
        "description": "Redis service target for security exercises.",
        "image": "redis:alpine",
        "internal_port": "6379/tcp",
        "access_mode": "service",
        "entry_path": "",
        "mem_limit": "256m",
        "needs_volume": False,
        "volume_path": "",
        "service": True
    },
    "ftp": {
        "name": "FTP",
        "description": "FTP service target for auth and misconfiguration exercises.",
        "image": "fauria/vsftpd",
        "internal_port": "21/tcp",
        "access_mode": "service",
        "entry_path": "",
        "mem_limit": "256m",
        "needs_volume": False,
        "volume_path": "",
        "service": True
    },
    "ssh": {
        "name": "SSH",
        "description": "SSH service target for hardening and attack practice.",
        "image": "linuxserver/openssh-server",
        "internal_port": "2222/tcp",
        "access_mode": "service",
        "entry_path": "",
        "mem_limit": "256m",
        "needs_volume": False,
        "volume_path": "",
        "service": True
    }
}

_client = None

def get_lab_network_name(user_id):
    return f"cyberlab-user-{int(user_id)}"

def _find_network_by_name(client, network_name):
    matches = client.networks.list(names=[network_name])
    for network in matches:
        if network.name == network_name:
            return network
    return None

def ensure_lab_network(user_id):
    client = get_client()
    if not client:
        raise Exception("Docker client not initialized. Is Docker running?")

    network_name = get_lab_network_name(user_id)
    existing = _find_network_by_name(client, network_name)
    if existing:
        return existing

    return client.networks.create(
        network_name,
        driver="bridge",
        check_duplicate=True,
        labels={
            "app": "cyberlab",
            "managed_by": "cyberlab",
            "scope": "user",
            "user_id": str(user_id)
        }
    )

def prune_user_network_if_unused(user_id):
    client = get_client()
    if not client:
        return False

    # Keep network if any user-owned container still exists.
    user_containers = client.containers.list(all=True, filters={"label": f"user_id={user_id}"})
    if user_containers:
        return False

    network_name = get_lab_network_name(user_id)
    network = _find_network_by_name(client, network_name)
    if not network:
        return False

    try:
        network.remove()
        return True
    except APIError:
        return False

def initialize_bwapp_database(port, timeout_seconds=90):
    install_url = f"http://127.0.0.1:{port}/install.php?install=yes"
    deadline = time.time() + timeout_seconds
    last_error = None

    while time.time() < deadline:
        try:
            request = Request(install_url, headers={"User-Agent": "CyberLab/1.0"})
            with urlopen(request, timeout=4) as response:
                body = response.read(65536).decode("utf-8", errors="ignore").lower()
                if response.status < 500 and ("installed successfully" in body or "bwaap has been installed successfully" in body or "bwapp has been installed successfully" in body or "login" in body):
                    return True
        except (URLError, HTTPError, TimeoutError, ConnectionError, OSError) as e:
            last_error = e

        time.sleep(2)

    raise Exception(f"bWAPP initialization failed on {install_url}. Last error: {last_error}")

def get_client():
    global _client
    if _client is None:
        try:
            _client = docker.from_env()
        except DockerException as e:
            print(f"Warning: Could not connect to Docker. Ensure Docker is running. Error: {e}")
            return None
    return _client

def ensure_image(lab_type):
    client = get_client()
    if not client:
        raise Exception("Docker client not initialized. Is Docker running?")
        
    config = LAB_CONFIGS.get(lab_type)
    if not config:
        raise Exception(f"Unknown lab type: {lab_type}")
        
    image_name = config['image']
    try:
        client.images.get(image_name)
    except docker.errors.ImageNotFound:
        print(f"Pulling {image_name}...")
        client.images.pull(image_name)

def start_container(port, user_id, lab_type="juice-shop"):
    client = get_client()
    if not client:
        raise Exception("Docker client not initialized. Is Docker running?")
    
    config = LAB_CONFIGS.get(lab_type)
    if not config:
        raise Exception(f"Unknown lab type: {lab_type}")
        
    ensure_image(lab_type)
    network = ensure_lab_network(user_id)
    network_name = network.name
    try:
        run_kwargs = {
            "image": config['image'],
            "detach": True,
            "ports": {config['internal_port']: port},
            "labels": {
                "app": f"{lab_type}-lab",
                "user_id": str(user_id),
                "managed_by": "cyberlab",
                "network_name": network_name
            },
            "network": network_name,
            "mem_limit": config['mem_limit'],
            "environment": config.get('environment', {})
        }
        
        # Optional command override per lab (for images whose defaults are not suitable for detached mode).
        if 'command' in config:
            run_kwargs["command"] = config['command']
        if config.get('override_entrypoint'):
            run_kwargs["entrypoint"] = []
        if config.get('interactive'):
            run_kwargs["stdin_open"] = True
            run_kwargs["tty"] = True

        # Handle persistent volume if required
        if config['needs_volume']:
            volume_name = f"{lab_type}-user-{user_id}"
            try:
                client.volumes.get(volume_name)
            except docker.errors.NotFound:
                client.volumes.create(name=volume_name)
            
            run_kwargs["volumes"] = {
                volume_name: {'bind': config['volume_path'], 'mode': 'rw'}
            }

        container = client.containers.run(**run_kwargs)

        if lab_type == "bwapp":
            try:
                initialize_bwapp_database(port)
            except Exception:
                container.remove(force=True)
                raise

        return container.id
    except APIError as e:
        raise Exception(f"Failed to start container: {e}")

def stop_container(container_id):
    client = get_client()
    if not client:
        raise Exception("Docker client not initialized. Is Docker running?")
    try:
        container = client.containers.get(container_id)
        container.stop()
        return True
    except docker.errors.NotFound:
        return False
    except APIError as e:
        raise Exception(f"Error stopping container: {e}")

def resume_container(container_id):
    client = get_client()
    if not client:
        raise Exception("Docker client not initialized. Is Docker running?")
    try:
        container = client.containers.get(container_id)
        container.start()
        return True
    except docker.errors.NotFound:
        return False
    except APIError as e:
        raise Exception(f"Error resuming container: {e}")

def remove_container(container_id):
    client = get_client()
    if not client:
        raise Exception("Docker client not initialized. Is Docker running?")
    try:
        container = client.containers.get(container_id)
        container.stop()
        container.remove()
        return True
    except docker.errors.NotFound:
        return False
    except APIError as e:
        raise Exception(f"Error removing container: {e}")

def get_container_status(container_id):
    client = get_client()
    if not client:
        return "error_docker_not_running"
    try:
        container = client.containers.get(container_id)
        return container.status
    except docker.errors.NotFound:
        return "not_found"
    except APIError:
        return "error"
