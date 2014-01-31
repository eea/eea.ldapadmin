$(function () {

    $('.tipsy-title').tipsy();

    var form = $('form[name=edit-leaders]');
    var leaders = form.find('input[name=leader]');
    var alternates = form.find('input[name=alternate_list:list]');

    leaders.change(function () {

        if($(this).attr('checked')) {
            var parent = $(this).parent();
            var parents = $(this).parents('tr');
            var alternate =  parents.find('input[name=alternate_list:list]');

            form.find('.leader_container').hide();
            alternates.show();
            parent.find('.leader_container').show();

            alternate.hide();
            alternate.attr('checked', false);
            parents.find('.alternate_container').hide();
        }

    }).change();

    alternates.change(function () {

        var parent = $(this).parent();
        var parents = $(this).parents('tr');
        var leader =  parents.find('input[name=leader]');

        if($(this).attr('checked')) {
            parent.find('.alternate_container').show();
            leader.hide()
            leader.attr('checked', false);
            parents.find('.leader_container').hide();
        } else {
            parent.find('.alternate_container').hide();
            leader.show()
        }

    }).change();

    // for setting PCPs in NFP-NRC tool
    $("div.nrc_role input[class=leader]").click(function(){
        var checkb = $(this);
        var role_div = checkb.parents("div.nrc_role");
        var role_id = role_div.attr("id");
        var user_id = checkb.val();
        $.post("set_pcp", {"role_id": role_id, "user_id": user_id},
                function (data){
                    var all_radios = $("input[class=leader]", role_div);
                    $("span.leader_container", role_div).hide();
                    all_radios.attr("checked", false);
                    var selected = $("input:radio[value=" + data.pcp + "]", role_div);
                    if (selected) {
                        selected.attr("checked", true);
                        selected.siblings("span.leader_container").show();
                        selected.tipsy({fade: true, trigger: 'manual',
                                      title: function(){return "PCP Saved";},
                                      gravity: 'e'});
                        selected.tipsy("show");
                        window.setTimeout(function(){checkb.tipsy("hide");}, 2000);
                    }
                },
                "json");
    });

});