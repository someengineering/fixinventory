extends Control

var data := {}
var accounts := []
var clouds := []

func _ready():
	read_data()
	
	for linechart in get_tree().get_nodes_in_group("metricviz_linechart"):
		linechart.set_data( get_metric_data( "", clouds[linechart.cloud_type] ) )
	
#	$MetricVizLineChartFullscreen.


func read_data():
	var file = File.new()
	file.open("res://data/prometheus_metrics.json", file.READ)
	var text = file.get_as_text()
	data = parse_json(text)
	file.close()
	
	for i in data.data.result:
		if !accounts.has(i.metric.account):
			accounts.append(i.metric.account)
		if !clouds.has(i.metric.cloud):
			clouds.append(i.metric.cloud)


func get_metric_data( account := "", cloud := "" ) -> Array:
	var result := []
	for i in data.data.result:
		var result_cloud = i.metric.cloud
		var result_account = i.metric.account
		
		if ((cloud == "" and account == "")  
		or (cloud == result_cloud and account == "")
		or (cloud == "" and account == result_account)
		or (cloud == result_cloud and account == result_account)):
			result.append( { "metrics" : i.metric, "values" : i.values } )
	
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
