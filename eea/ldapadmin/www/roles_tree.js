$(function() {

var www_url = '/++resource++eea.ldapadmin-www';

function decorate_subrole_links(sub_roles, level) {
    $('> tr', sub_roles).each(function() {
        var tr = $(this);
        tr.data('subroles-level', level);
        var arrow = make_arrow().addClass('arrow-normal').click(subrole_expand);
        var arrow2 = make_arrow().addClass('arrow-down');
        arrow2.hide().click(subrole_collapse);
        jQuery("#expand-all-button").click(subrole_expand_all);
        jQuery("#collapse-all-button").click(subrole_collapse_all);
        var padding = '';
        for(var c = 0; c < level; c++) { padding = padding + "&nbsp;&nbsp;&nbsp;"; }
        $('> td > a', tr).before(padding);
        $('> td > a.has-children', tr).before(arrow, arrow2);
    });
}

decorate_subrole_links($('table.sub-roles > tbody'), 0);

function make_arrow() {
    return $('<'+'img class="roles-tree-arrow help-tooltip" src="'+www_url+'/s.gif">');
}

function subrole_expand(evt) {
    if(typeof evt != 'undefined'){
        evt.preventDefault();
    }
    var tr = $(this).parent().parent();
    var subroles_tr_list = tr.data('subroles-box');
    if(subroles_tr_list === null || subroles_tr_list == undefined) {
        fetch_subroles(tr);
    } else {
        subroles_tr_list.show();
    }
    $('> td > .roles-tree-arrow.arrow-normal', tr).css('display', 'none');
    $('> td > .roles-tree-arrow.arrow-down', tr).css('display', 'inline');
}

function subrole_collapse(evt) {
    if(typeof evt != 'undefined'){
        evt.preventDefault();
    }
    var tr = $(this).parent().parent();

    tr.data('subroles-box').hide();
    $('> td > .roles-tree-arrow.arrow-normal', tr).css('display', 'inline');
    $('> td > .roles-tree-arrow.arrow-down', tr).css('display', 'none');
}

function subrole_expand_all(){
    var arrows = jQuery(".arrow-normal:visible");
    var i;
    for(i=0; i < arrows.length; i++){
        subrole_expand.call(arrows[i]);
    }
}

function subrole_collapse_all(){
    var arrows = jQuery(".arrow-down:visible");
    var i;
    for(i=0; i < arrows.length; i++){
        subrole_collapse.call(arrows[i]);
    }
}

function fetch_subroles(tr) {
    var a = tr.children().first().find('a');
    var href = a.attr('href');
    var name = a.text();
    var loading_td = $('<'+'td colspan="2">').text("Loading " + name + " ...");
    var loading_tr = $('<'+'tr>').append(loading_td).insertAfter(tr);
    tr.data('subroles-box', loading_tr);

    $.get(href, function(data) {
        tr.data('subroles-box').remove();
        var kid_sub_roles = $('table.sub-roles > tbody', data);
        decorate_subrole_links(kid_sub_roles, tr.data('subroles-level')+1);
        var subroles_tr_list = $('tr', kid_sub_roles);
        if(subroles_tr_list.length < 1) {
            var arrows = $('.roles-tree-arrow', tr).hide();
            make_arrow().addClass('arrow-blank').insertBefore(arrows[0]);
        }
        subroles_tr_list.insertAfter(tr);
        tr.data('subroles-box', subroles_tr_list);
    });
}

});
