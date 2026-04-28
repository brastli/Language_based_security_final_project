def run(user_input):
    return eval(user_input)

if __name__ == "__main__":
    print(run("__import__('os').getcwd()"))