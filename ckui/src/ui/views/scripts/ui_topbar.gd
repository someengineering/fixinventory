extends Control

enum states {GRAPH, SEARCH, DASHBOARD, QUERY}

onready var buttons = [$Buttons/TopButton_Nodes, $Buttons/TopButton_Search, $Buttons/TopButton_Dashboard, $Buttons/TopButton_Query]

func _ready():
	for i in buttons.size():
		buttons[i].connect("pressed", self, "change_section", [i])


func change_button(old_state, new_state):
	buttons[old_state].active = false
	buttons[new_state].active = true

func change_section(state_id):
	_g.interface.state = state_id
