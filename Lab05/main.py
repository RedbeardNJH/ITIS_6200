from BLPmodel import System as BLPsys

def start_sys():
    # Start new BLP System
    blpSys = BLPsys()
    # Add System Subjects
    # I am aware the order is wrong, I flip starting and max level in the BLPmodel.py
    blpSys.add_subject("Alice", "U", "S")
    blpSys.add_subject("Bob", "C", "C")
    blpSys.add_subject("Eve", "U", "U")
    # Add System Objects
    blpSys.add_object("pub.txt", "U")
    blpSys.add_object("emails.txt", "C")
    blpSys.add_object("username.txt", "S")
    blpSys.add_object("password.txt", "TS")

    return blpSys

def user_in():
    print("Options: ")
    print("  [1-18] Run a specific test case (1 to 18)")
    print("  [A] Run all test cases sequentially")
    print("  [Q] Quit")
    inp = input("Enter choice: ").lower()
    try: 
        con_inp = int(inp)
        return con_inp
    except ValueError:
        return inp

CASES = {
    1:  ("Alice reads emails.txt",                                                          [("read", "Alice", "emails.txt")]),
    2:  ("Alice reads password.txt",                                                        [("read", "Alice", "password.txt")]),
    3:  ("Eve reads pub.txt",                                                               [("read", "Eve", "pub.txt")]),
    4:  ("Eve reads emails.txt",                                                            [("read", "Eve", "emails.txt")]),
    5:  ("Bob reads password.txt",                                                          [("read", "Bob", "password.txt")]),
    6:  ("Alice reads emails.txt then writes to pub.txt",                                   [("read", "Alice", "emails.txt"), ("write", "Alice", "pub.txt")]),
    7:  ("Alice reads emails.txt then writes to password.txt",                              [("read", "Alice", "emails.txt"), ("write", "Alice", "password.txt")]),
    8:  ("Alice reads/writes emails.txt, then reads username.txt and writes emails.txt",    [("read", "Alice", "emails.txt"), ("write", "Alice", "emails.txt"), ("read", "Alice", "username.txt"), ("write", "Alice", "emails.txt")]),
    9:  ("Alice reads username.txt, writes emails.txt, reads password.txt, writes it",      [("read", "Alice", "username.txt"), ("write", "Alice", "emails.txt"), ("read", "Alice", "password.txt"), ("write", "Alice", "password.txt")]),
    10: ("Alice reads pub.txt, writes emails.txt. Bob reads emails.txt",                    [("read", "Alice", "pub.txt"), ("write", "Alice", "emails.txt"), ("read", "Bob", "emails.txt")]),
    11: ("Alice reads pub.txt, writes username.txt. Bob reads username.txt",                [("read", "Alice", "pub.txt"), ("write", "Alice", "username.txt"), ("read", "Bob", "username.txt")]),
    12: ("Alice reads pub.txt, writes password.txt. Bob reads password.txt",                [("read", "Alice", "pub.txt"), ("write", "Alice", "password.txt"), ("read", "Bob", "password.txt")]),
    13: ("Alice reads pub.txt, writes emails.txt. Eve reads emails.txt",                    [("read", "Alice", "pub.txt"), ("write", "Alice", "emails.txt"), ("read", "Eve", "emails.txt")]),
    14: ("Alice reads emails.txt, writes pub.txt. Eve reads pub.txt",                       [("read", "Alice", "emails.txt"), ("write", "Alice", "pub.txt"), ("read", "Eve", "pub.txt")]),
    15: ("Alice sets level to S, reads username.txt",                                       [("set_level", "Alice", "S"), ("read", "Alice", "username.txt")]),
    16: ("Alice reads emails.txt, sets level to U, writes pub.txt. Eve reads pub.txt",      [("read", "Alice", "emails.txt"), ("set_level", "Alice", "U"), ("write", "Alice", "pub.txt"), ("read", "Eve", "pub.txt")]),
    17: ("Alice reads username.txt, sets level to C, writes emails.txt. Eve reads it",      [("read", "Alice", "username.txt"), ("set_level", "Alice", "C"), ("write", "Alice", "emails.txt"), ("read", "Eve", "emails.txt")]),
    18: ("Eve reads pub.txt then reads emails.txt",                                         [("read", "Eve", "pub.txt"), ("read", "Eve", "emails.txt")]),
}

def case(number):
    if number not in CASES:
        return "Number requested out of range"
    
    description, steps = CASES[number]
    system = start_sys()
    result = True

    print(f"================== CASE #{number} ====================")
    print(f"{description}")

    for step in steps:
        if step[0] == "read":
            result = system.read(step[1], step[2])
        elif step[0] == "write":
            result = system.write(step[1], step[2])
        elif step[0] == "set_level":
            result = system.set_level(step[1], step[2])

    system.print_system_state()
    print("="*50)


if __name__ == "__main__":
    print("="*50)
    print("Bell-LaPadula (BLP) Simulator CLI")
    print("="*50)
    while True:
        choice = user_in()
        if type(choice) is int:
            case(choice)
        elif choice == "a":
            for x in range(17):
                case(x+1)
        elif choice == "q":
            break
        else:
            print("bad input")