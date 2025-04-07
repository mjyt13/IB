import os,json
users_json_path = "users.json"

def get_users():

    if not os.path.exists(users_json_path):
        restrictions = {
            "lower_letters": True,
            "upper_letters": True,
            "digits": True,
            "special": True
        }
        admin={
            "username": "ADMIN",
            "password": "",
            "banned": False,
            "restrictions": restrictions
        }
        users = {"ADMIN": admin}
        with open(users_json_path,"w") as file:
            json.dump(users,file)
        return users
    else:
        with open(users_json_path,"r") as file:
            return json.load(file)

def save_users(users):
    with open(users_json_path, "w") as file:
        json.dump(users, file)
