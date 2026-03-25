levels = {
    "U" : 1,
    "C" : 2,
    "S" : 3,
    "TS" : 4
}

class Subject:
    def __init__(self, name, max_level, current_level):
        self.name = name
        self.max_level = max_level
        self.current_level = current_level

class Object:
    def __init__(self, name, level):
        self.name = name
        self.level = level

class System:
    def __init__(self):
        self.subjects = {}
        self.objects = {}
        #print("Created BLP System")

    def add_subject(self, name, current_level, max_level):
        new_subject = Subject(name, max_level, current_level)
        if (levels[current_level] > levels[max_level]):
            print("Cannot add subject. Level is higher than maximum allowed level.")
            return
        self.subjects[name] = new_subject
        #print(f"added subject {new_subject.name}")

    def add_object(self, name, level):
        self.objects[name] = Object(name, level)
        #print(f"added subject {self.objects[name].name}")

    def validate_levels(self, subject_name, object_name):
        return levels[self.subjects[subject_name].current_level] == levels[self.objects[object_name].level]

    def set_level(self, subject_name, new_level):
        # CONSTRAINT:
        if levels[new_level] <= levels[self.subjects[subject_name].current_level]:
            #print(f"Cannot set new level for {subject_name}. Current level ({self.subjects[subject_name].current_level}) exceedes new level ({new_level})")
            return
        self.subjects[subject_name].current_level = new_level
        #print("Successfully updated to new level")

    def read(self, subject_name, object_name):
        print(f">ACTION: {subject_name} READ {object_name}...")
        #DYNAMIC LEVELING (Object level > Subject Current Level && Object level < Subject Maximum Level -> Raise Subject Current Level)
        if levels[self.objects[object_name].level] > levels[self.subjects[subject_name].current_level]:
            #print("Object level > Subject Current Level")
            if levels[self.objects[object_name].level] <= levels[self.subjects[subject_name].max_level]:
                print(f">INFO: raising {subject_name}'s level to {self.objects[object_name].level}")
                self.set_level(subject_name, self.objects[object_name].level)
        #CONSTRAINT (check if allowed to read)
        allowed = levels[self.subjects[subject_name].current_level] >= levels[self.objects[object_name].level]
        if allowed: print(f">ALLOW: Obj Lvl {self.objects[object_name].level} <= Subj Max {self.subjects[subject_name].current_level}")
        else: print(f">FAIL: Obj Lvl {self.objects[object_name].level} NOT <= Subj Max {self.subjects[subject_name].current_level}")

    def write(self, subject_name, object_name):
        print(f">ACTION: {subject_name} WRITE {object_name}...")
        allowed = levels[self.subjects[subject_name].current_level] <= levels[self.objects[object_name].level]
        if allowed: print(f">ALLOW: Obj Lvl {self.objects[object_name].level} >= Subj Max {self.subjects[subject_name].current_level}")
        else: print(f">FAIL: Obj Lvl {self.objects[object_name].level} NOT >= Subj Max {self.subjects[subject_name].current_level}")
    
    def print_system_state(self):
        print("-----------Current BLP State-----------")
        for s in self.subjects.values():
            print(f"[Subject] {s.name}: Curr={s.current_level}, Max={s.max_level}")
        for o in self.objects.values():
            print(f"[Object] {o.name}: Lvl={o.level}")
        print("---------------------------------------")