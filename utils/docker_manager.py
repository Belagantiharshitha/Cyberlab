import docker
from docker.errors import DockerException, APIError

LAB_CONFIGS = {
    "juice-shop": {
        "name": "OWASP Juice Shop",
        "description": "Modern web application packed with severe security flaws.",
        "image": "bkimminich/juice-shop",
        "internal_port": "3000/tcp",
        "mem_limit": "1g",
        "needs_volume": True,
        "volume_path": "/juice-shop/data"
    },
    "dvwa": {
        "name": "DVWA",
        "description": "Classic PHP/MySQL vulnerable utility for foundational SQLi & XSS.",
        "image": "vulnerables/web-dvwa",
        "internal_port": "80/tcp",
        "mem_limit": "512m",
        "needs_volume": False,
        "volume_path": ""
    },
    "bwapp": {
        "name": "bWAPP (Buggy Web App)",
        "description": "Deliberately insecure application featuring 100+ vulnerabilities.",
        "image": "raesene/bwapp",
        "internal_port": "80/tcp",
        "mem_limit": "512m",
        "needs_volume": False,
        "volume_path": ""
    },
    "webgoat": {
        "name": "OWASP WebGoat",
        "description": "Insecure enterprise Java EE application maintained by OWASP.",
        "image": "webgoat/webgoat-8.0",
        "internal_port": "8080/tcp",
        "mem_limit": "1g",
        "needs_volume": False,
        "volume_path": ""
    }
}

_client = None

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
    try:
        run_kwargs = {
            "image": config['image'],
            "detach": True,
            "ports": {config['internal_port']: port},
            "labels": {"app": f"{lab_type}-lab", "user_id": str(user_id)},
            "mem_limit": config['mem_limit'],
            "environment": {} # Add specific environment vars if needed later
        }

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
