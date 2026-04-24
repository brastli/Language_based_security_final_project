def inputInt():
    '''
    Take an int input and return it after checking type
    '''
    userInput = input("Enter a number: ")
    try:
        userInput = int(userInput)
    except (TypeError, ValueError):
        raise ValueError("Invalid integer input")
    if type(userInput) != int:
        raise ValueError("Invalid integer input")
    return userInput