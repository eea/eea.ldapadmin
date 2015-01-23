if (!Function.prototype.bind) {
  Function.prototype.bind = function(oThis) {
    if (typeof this !== 'function') {
      // closest thing possible to the ECMAScript 5
      // internal IsCallable function
      throw new TypeError('Function.prototype.bind - what is trying to be bound is not callable');
    }

    var aArgs   = Array.prototype.slice.call(arguments, 1),
        fToBind = this,
        fNOP    = function() {},
        fBound  = function() {
          return fToBind.apply(this instanceof fNOP && oThis
                 ? this
                 : oThis,
                 aArgs.concat(Array.prototype.slice.call(arguments)));
        };

    fNOP.prototype = this.prototype;
    fBound.prototype = new fNOP();

    return fBound;
  };
}


var MembersEditor = function(search_url){
    this.widget = $('#current_members');
    this.SEARCH_URL = search_url;

    // Left side: display, edit areas
    this.target_widget = $("#target_widget");
    this.members_table = $("#members_table");
    this.advanced_edit_form = $("#advanced_edit_form");
    this.members_textarea = $("textarea", this.widget);

    // Left side: buttons
    this.remove_selected_btn = $("#members_remove_selected");
    this.save_advanced_members_btn = $("#save_advanced_members");
    this.cancel_advanced_members_btn = $("#cancel_advanced_members");
    this.advanced_edit_btn = $("#members_advanced_edit");

    // Left side: handlers
    this.remove_selected_btn.on('click', this.handle_remove_selected_members.bind(this));
    this.advanced_edit_btn.on('click', this.toggle_advanced_edit.bind(this));
    this.save_advanced_members_btn.on('click', this.handle_save_advanced.bind(this));
    this.cancel_advanced_members_btn.on('click', this.handle_cancel_advanced.bind(this));

    // Right side: display, edit areas
    this.source_widget = $("#source_widget");
    this.members_source_table = $("#members_source_table");
    this.members_search_table = $("#members_search_table");
    this.search_eionet_text = $("#eionet_search", this.widget);
    this.members_filter_text = $("#members_filter", this.widget);
    this.filter_counter = $("#members_counter");

    // Right side: buttons
    this.eionet_filter_btn = $("#eionet_filter_btn");
    this.add_selected_btn = $("#add_selected_btn");
    this.members_filter_btn = $("#members_filter_btn");

    // handlers for right side box
    this.eionet_filter_btn.on('click', this.search_eionet.bind(this));
    this.add_selected_btn.on('click', this.handle_add_selected_members.bind(this));
    this.members_filter_btn.on('click', this.handle_members_filter.bind(this));

    // generic handlers
    this.widget.on('mouseenter', 'tr', this.handle_mouse_over.bind(this));
    this.widget.on('mouseleave', 'tr', this.handle_mouse_out.bind(this));
    //
    // this.widget.hoverIntent({
    //     over: this.handle_mouse_over.bind(this),
    //     out: this.handle_mouse_out.bind(this),
    //     selector: 'tr'
    // });
    this.member_to_names = this._extract_members_from_source(this.source_widget);

    this.widget.on('click', '.btn_add', this.handle_add_member.bind(this));
    this.widget.on('click', '.btn_delete', this.handle_delete_member.bind(this));

    this.$tpl_button_add = $('<button class="actions btn_add"><i class="fa fa-plus"></i></button>');
    this.$tpl_button_delete = $('<button class="actions btn_delete"><i class="fa fa-trash"></i></button>');

    this.update_filter_counter();
};


MembersEditor.prototype = {

    update_filter_counter: function(){
        this.filter_counter.html($("tbody tr:visible", this.source_widget).length.toString());
    },

    handle_add_member: function(event){
        var $btn = $(event.target);
        var username = $btn.parents('tr').find('.user_id').html().toString();
        this._add_users_to_table(this.target_widget, [username], this.$tpl_button_delete);
        return false;
    },

    handle_delete_member: function(event){
        var $btn = $(event.target);
        var username = $btn.parents('tr').find('.user_id').html().toString();
        this._remove_users_from_table(this.target_widget, [username]);
        return false;
    },

    handle_mouse_over: function(event){
        $('.actions', $(event.target).parent()).show();
    },

    handle_mouse_out: function(event){
        $('.actions', $(event.target).parent()).hide();
    },

    handle_members_filter: function(){
        var c = 0;
        var filter = $("#members_filter").val().toLowerCase();

        _.each($("tbody tr", this.members_source_table), function(el){
            if ($(el).html().toLowerCase().search(filter.toLowerCase()) > -1){
                $(el).show();
                this.filter_counter.html((++c).toString());
            } else {
                $(el).hide();
            }
        }, this);
        return false;
    },

    handle_remove_selected_members: function(){
        var to_remove = [];
        _.each(this.target_widget.find('input[type="checkbox"]:checked'),
                function(el){
                    to_remove.push($(el).attr('value'));
                });

        var usernames = this._textarea_to_usernames(this.members_textarea);
        var to_save = _.difference(usernames, to_remove);
        this.members_textarea.html(to_save.join('\n'));

        this._remove_users_from_table(this.target_widget, to_remove);

        return false;
        },

    handle_add_selected_members: function(){
        var to_add = [];
        _.each(this.source_widget.find('input[type="checkbox"]:checked:visible'),
                function(el){
                    to_add.push($(el).attr('value'));
                });

        var usernames = this._textarea_to_usernames(this.members_textarea);

        var to_save = _.union(usernames, to_add);
        this.members_textarea.html(to_save.join('\n'));

        this._add_users_to_table(this.target_widget, to_add, this.$tpl_button_delete);

        return false;
    },

    toggle_advanced_edit: function(){
        this.save_advanced_members_btn.toggle();
        this.advanced_edit_form.toggle();
        this.members_table.toggle();
        this.remove_selected_btn.toggle(); this.advanced_edit_btn.toggle();
        return false;
    },

    handle_cancel_advanced: function(){
        var usernames = this._table_to_usernames(this.members_table);
        this.members_textarea.html(usernames.join('\n'));
        this.members_textarea.val(usernames.join('\n'));
        this.toggle_advanced_edit();
        return false;
    },

    handle_save_advanced: function() {
        var table = this.target_widget;
        // this._clean_members_textarea();
        var usernames_to_save = this._textarea_to_usernames(this.members_textarea);
        var usernames_in_table = this._table_to_usernames(table);

        var usernames_to_add = _.difference(usernames_to_save, usernames_in_table);
        var usernames_to_remove = _.difference(usernames_in_table, usernames_to_save);

        this._remove_users_from_table(table, usernames_to_remove);
        this._add_users_to_table(table, usernames_to_add, this.$tpl_button_delete);

        this.toggle_advanced_edit();

        return false;
    },

    _add_users_to_table: function(table, usernames, btn){
        _.each(usernames, function(username){
            this._add_user_to_table(table, username, btn);
        }, this);
    },

    _textarea_to_usernames: function(textarea){
        return _.filter(
                _.map(
                    textarea.val().split('\n'), 
                    function(s){ return s.trim(); }
                    ),
                function(s) { return s.length > 0; }
            );
    },

    _table_to_usernames: function(table){
        var usernames = [];
        table.find('tbody tr').each(function(){
            var username = $(this).find('td.user_id').html();
            var fullname = $(this).find('td.fullname').html();
            if (username !== null) usernames.push(username.toString());
        });
        return usernames;
    },

    _remove_users_from_table: function(table, usernames) {
        _.each(table.find('tbody tr'), function(el){
            var username = $(el).find('td.user_id').html().trim().toString();
            if (_.contains(usernames, username)) el.remove();
        }, this);
    },

    _add_user_to_table: function(table, username, $btn){
        // TODO: flash the row when duplicate userid is added
        var fullname = this.member_to_names[username] || ' - ';
        var user = {user_id: username, fullname: fullname};
        var row = $('<tr>')
            .append($('<td><input type="checkbox" value="' + user.user_id + '""/></td>'))
            .append($("<td class='user_id'>").html(user.user_id))
            .append($("<td class='fullname'>").html(user.fullname || '-'))
            .append($('<td></td>').append($btn.clone()));
        table.find('tbody').append(row);
    },

    search_eionet: function(){
        //
        var filter = $("#eionet_search").val().toString().trim();
        if(!filter.length) return false;

        var self = this;
        this.members_search_table.find('tbody tr').remove();

        $.getJSON(this.SEARCH_URL, {filter:filter}, function(data){
            _.each(data, function(obj, index){
                self.member_to_names[obj.id] = obj.full_name;
                self._add_user_to_table(
                    self.members_search_table,
                    obj.id,
                    self.$tpl_button_add
                );
            });
        });
        return false;
    },

    _extract_members_from_source: function(source){
        var res = {};
        source.find('tbody tr:visible').each(function(){
            var username = $(this).find('td.user_id').html();
            var fullname = $(this).find('td.fullname').html();
            if (username !== null) res[username] = fullname;
        });

        return res;
    }

};
