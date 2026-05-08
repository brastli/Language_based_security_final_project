import yaml

def run(user_input):
    return yaml.load(user_input, Loader=yaml.Loader)

if __name__ == "__main__":
    sample = "a: 1\nb: 2\nc: 3"
    print(run(sample))