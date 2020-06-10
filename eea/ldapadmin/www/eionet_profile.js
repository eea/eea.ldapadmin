$(document).ready(function(){
    $("div.eionet-profile a.trigger").click(function(){
       $(this).hide();
       var parentdiv = $(this).parent("div.eionet-profile");
       var service = $("h2", parentdiv).text().trim();
       var uid = parentdiv.data("uid");
       var rolesdiv = $("div.roles", parentdiv);
       rolesdiv.show();
       $.post("get_endpoint", {service: service, userid: uid}, function(data){
            var ul = $("<ul>");
            for(var i=0; i<data[uid].length; i++){
                var role = data[uid][i];
                var li = $("<li>" + role.roles.join(", ") + " in " +
                "<a href=\"" + role.ob_url + "\" target=\"blank\">" +
                    role.ob_title + "</a></li>");
                ul.append(li);
            }
            if (data[uid].length) {
                rolesdiv.html("");
                rolesdiv.append(ul);
            } else {
                rolesdiv.html("No roles found for this user in " + service);
            }
        }, 'json');
       });
});
