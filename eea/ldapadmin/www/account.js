$(document).ready(function(){
	$('.hidden').hide();

	/**
	 * For tables with select all option check if all checkboxes are selected.
	 * If one of them is unchecked then uncheck the main select all checkbox.
	*/
	$('.account-datatable tbody tr td.checkbox-td input[type="checkbox"]').click(function(){
		name = $(this).attr('name').split(":list")[0];
		if($(this).attr('class') != 'selectall'){
			if($(this).attr('checked') == false){
				$('.selectall').attr('checked', false);
				$(this).attr('checked', false);
			}else {
				var not_all = false;
				$.each($('.account-datatable tbody tr td.checkbox-td input[@name="' + name + '"][type="checkbox"]'), function(i, e){
					if($(this).attr('checked') == false){
						not_all = true;
					}
				});
				if(not_all == false){
					$('.selectall').attr('checked', true);
				}
			}
		}
	});
});

function toggleView(selector){
	$(selector).toggle();
	return false;
}

function selectAll(name, additional_class){
    var table_class = '.account-datatable';
    if ( additional_class ){
        table_class += '.' + additional_class;
    }

    $('' + table_class + ' tbody tr td.checkbox-td input[@name="' + name + '"][type="checkbox"]').each(function(){
        $this = $(this);
        if ( $this.attr('checked') == true ) {
            $this.attr('checked', false);
        }else {
            $this.attr('checked', true);
        }
    });
    return false;
}

(function(){
	jQuery(document).ready(function(){
		/** User admin **/
		jQuery("input[name=send_confirmation]").click(function(ev){
			if(this.checked){
				jQuery("#confirmation_email").show('blind', {}, 800);
				jQuery.post(
					'confirmation_email',
					{'first_name:utf8:ustring': jQuery("#edit-first_name").val(),
					 user_id: jQuery("#edit-id").val()},
					 function(data){
						jQuery("#confirmation_email pre").text(data);
					 }
				);
			}
			else{
				jQuery("#confirmation_email").hide('blind', {}, 600);
			}
		});

		/** Roles editor **/
		jQuery("input#shortcut_queries").click(function(ev){
			var shortcut = jQuery(document.search.action).val();
			var country = document.search.shortcut_country.value;
			var input = jQuery('#search-roles-input');
			if (!country)
				country = '*';
			switch(shortcut){
				case 'country':
					input.val('eionet-*-'+country);
					break;
				case 'country_nfp':
					input.val('eionet-nfp-*-'+country);
					break;
				case 'country_nrc':
					input.val('eionet-nrc-*-'+country);
					break;
				default: break;
			}
			document.search.submit();
		});
	});
})();

// edit role name
(function($){

	var set_role_name = function (ev){
		var role_name = $("input[name=role_name]", $(this).parent()).val();
		var role_id = $("input[name=role_id]", $(this).parent()).val();
		if(!role_name){
			alert("You must provide a name for the role");
		}
		else {
            var pathname = window.location.pathname;
			$.post(pathname + '/edit_role_name',
				{role_id: role_id, 'role_name:utf8:ustring': role_name},
				function(data){
					console.log(data);
					if(data.error)
						alert(data.error);
					else{
						$('div#role-name h1').text(role_name);
						$('div#role-name-edit').hide(200, function(){
							$('div#role-name').show();
						});
					}
				},
				'json');
        }
	};

	$(document).ready(function(){
		$("#edit-role-description-arrow").click(function(ev){
			$('div#role-name').hide(200, function(){
				$('div#role-name-edit').show();
			});
		});
		$("#role-name-edit").keypress(function(ev){
			if (ev.keyCode == 13)
				set_role_name(ev);
		});
		$("#role-name-edit input[type=submit]").click(set_role_name);
	});
})(jQuery);
