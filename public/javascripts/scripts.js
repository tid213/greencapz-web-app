$(window).ready(function () {
  var menu = $(".nav-link[href='" + location.pathname + "']").attr("id");

  $(document).ready(function () {
    var currentID = menu;
    localStorage.setItem("activeTab", currentID);
    var activeTab = localStorage.getItem("activeTab");
    if (activeTab != "") {
      $("#" + activeTab).addClass("active");
    }
  });
});
