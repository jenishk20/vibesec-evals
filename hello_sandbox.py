import modal

app = modal.App.lookup("vulnbench", create_if_missing=True)

sb = modal.Sandbox.create(app=app, timeout=60)

result = sb.exec("python", "-c", "print('hello from sandbox')")
result.wait()

print("OUTPUT:", result.stdout.read())
print("EXIT CODE:", result.returncode)

sb.terminate()
