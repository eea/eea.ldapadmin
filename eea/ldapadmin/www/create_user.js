$(function() {
    var checkFields = function() {
      var fname = $('#edit-first_name');
      var lname = $('#edit-last_name');
      var email = $('#edit-email');
      var loader = $('<div class="loader"></div>');
        if (fname.val() && lname.val() && email.val()) {
          $('#users-container').append(loader);
          var data = {
            first_name: fname.val(),
            last_name: lname.val(),
            email: email.val()
          }
          $.ajax({
              url: url_search_duplicates,
              data: data,
              success: function(data) {
                  $('#users-container').html(data);
              }
          });
       }
    };
    var onBlur = function() {
        if ($.trim($(this).val()) == "") {
            return;
        }
        checkFields();
    }
    $('form[name="create-account"]').find(":input").blur(onBlur);
    checkFields();
});
