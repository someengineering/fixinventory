extends Control

var data := {}
var accounts := []
var clouds := []


func _ready():
	read_data()

	for linechart in get_tree().get_nodes_in_group("metricviz_linechart"):
		linechart.set_data(
			get_metric_data("", clouds[min(linechart.cloud_type, clouds.size() - 1)])
		)


func read_data():
	var file = File.new()
	if file.file_exists(_g.PROMETHEUS_METRICS_JSON_PATH) and !_g.use_example_data:
		file.open(_g.PROMETHEUS_METRICS_JSON_PATH, file.READ)
		var text = file.get_as_text()
		data = parse_json(text)
		file.close()
	else:
		var example_data_file = load("res://scripts/tools/example_data.gd")
		var example_data = example_data_file.new()
		data = example_data.tsdb_data.duplicate()

	for i in data.data.result:
		if !accounts.has(i.metric.account):
			accounts.append(i.metric.account)
		if !clouds.has(i.metric.cloud):
			clouds.append(i.metric.cloud)


func get_metric_data(account := "", cloud := "") -> Array:
	var result := []
	for i in data.data.result:
		var result_cloud = i.metric.cloud
		var result_account = i.metric.account

		if (
			(cloud == "" and account == "")
			or (cloud == result_cloud and account == "")
			or (cloud == "" and account == result_account)
			or (cloud == result_cloud and account == result_account)
		):
			result.append({"metrics": i.metric, "values": i.values})

	return result


func deactivate():
	for c in get_tree().get_nodes_in_group("metricviz_linechart"):
		c.is_active = false
	$DashboardActivateTimer.stop()


func activate():
	for c in get_tree().get_nodes_in_group("metricviz"):
		c.play_anim()
	$DashboardActivateTimer.start()


func _on_DashboardActivateTimer_timeout():
	for c in get_tree().get_nodes_in_group("metricviz_linechart"):
		c.is_active = true
