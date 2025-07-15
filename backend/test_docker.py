import docker

client = docker.from_env()
print("Listing containers...")
for c in client.containers.list():
    print(f"Container: {c.name}")

print("Running a quick Nmap test container...")
out = client.containers.run(
    image="instrumentisto/nmap",
    command="nmap -Pn -p 80 scanme.nmap.org",
    remove=True,
    stdout=True,
    stderr=True
)
print("Nmap output:")
print(out.decode())
