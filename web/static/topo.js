switches = null;
containers = null;

$(document).ready(function() {
	$.getJSON("../switch.json", function(data){ switches = data; });
    $.getJSON("../container.json", function(data){ containers = data; show_topo(); });
});

function show_topo() {
    console.log(a = switches);
    var canvas = document.getElementById("topo");
    var stage = new JTopo.Stage(canvas);
    var scene = new JTopo.Scene(stage);

    var nodes = {};

    for (var name in switches)
    {
        nodes[name] = new JTopo.Node(name);
        nodes[name].setLocation(500*Math.random()+200,150*Math.random()+50);
        nodes[name].layout = {type: 'tree', width:180, height: 100};
        scene.add(nodes[name]);
    }

    for (var name in switches)
    {
        for (var key in switches[name])
        {
            if (switches[name][key] == 'on')
            {
                var link = new JTopo.Link(nodes[name], nodes[key]);
                scene.add(link);
            }
        }
    }

    for (var name in containers)
    {
        nodes[name] = new JTopo.CircleNode(name);
        nodes[name].setLocation(700*Math.random()+100, 200*Math.random()+350);
        nodes[name].fillColor = '100,225,0';
        scene.add(nodes[name]);
    }

    for (var name in containers)
    {
        if (containers[name].connect)
        {
            var link = new JTopo.Link(nodes[name], nodes[containers[name].connect]);
            link.strokeColor = '0,255,255';
            scene.add(link);

        }
    }
}

function count(o) {
    var t = typeof o;
    if(t == 'string'){
        return o.length;
    }
    else if(t == 'object'){
        var n = 0;
        for(var i in o){
                n++;
        }
        return n;
    }
    return false;
}
