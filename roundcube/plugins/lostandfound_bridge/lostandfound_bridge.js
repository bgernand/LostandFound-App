(function () {
  function qs(sel) {
    return document.querySelector(sel);
  }

  function selectedUid() {
    if (window.rcmail && rcmail.env && rcmail.env.uid) {
      return rcmail.env.uid;
    }
    if (window.rcmail && rcmail.message_list && typeof rcmail.message_list.get_selection === "function") {
      var selected = rcmail.message_list.get_selection();
      if (selected && selected.length === 1) {
        return selected[0];
      }
    }
    return "";
  }

  function currentFolder() {
    return (window.rcmail && rcmail.env && (rcmail.env.mailbox || rcmail.env.mbox)) || "";
  }

  function buildLink(baseUrl) {
    var folder = currentFolder();
    var uid = selectedUid();
    if (!folder || !uid) {
      return "";
    }
    return baseUrl + "?folder=" + encodeURIComponent(folder) + "&uid=" + encodeURIComponent(uid);
  }

  function addSidebarBackLink() {
    if (!window.rcmail || !rcmail.env || !rcmail.env.laf_bridge || !rcmail.env.laf_bridge.dashboard_url) {
      return;
    }

    var taskMenu =
      qs("#taskmenu") ||
      qs(".task-menu") ||
      qs("nav[aria-label='Tasks']") ||
      qs(".listing.iconized");
    if (!taskMenu || qs("#task-lostfound")) {
      return;
    }

    var referenceItem =
      qs("#task-mail") ||
      qs("#task-addressbook") ||
      taskMenu.querySelector("li") ||
      taskMenu.querySelector("a");

    var item = document.createElement("li");
    item.id = "task-lostfound";
    item.className = "button lostfound";

    var link = document.createElement("a");
    link.href = rcmail.env.laf_bridge.dashboard_url;
    link.textContent = "Lost & Found";
    link.setAttribute("title", "Back to Lost & Found");
    link.addEventListener("click", function (event) {
      event.preventDefault();
      window.location.href = rcmail.env.laf_bridge.dashboard_url;
    });
    item.appendChild(link);

    if (referenceItem && referenceItem.tagName && referenceItem.tagName.toLowerCase() === "li" && referenceItem.parentNode === taskMenu) {
      taskMenu.insertBefore(item, referenceItem.nextSibling);
      return;
    }

    if (referenceItem && referenceItem.parentNode && referenceItem.parentNode.tagName && referenceItem.parentNode.tagName.toLowerCase() === "li" && referenceItem.parentNode.parentNode === taskMenu) {
      taskMenu.insertBefore(item, referenceItem.parentNode.nextSibling);
      return;
    }

    taskMenu.appendChild(item);
  }

  function addButtonRow() {
    if (!window.rcmail || !rcmail.env || !rcmail.env.laf_bridge || !rcmail.env.laf_bridge.enabled) {
      return;
    }
    if (currentFolder() !== rcmail.env.laf_bridge.unassigned_folder) {
      return;
    }

    var target = qs("#layout-content") || qs("#layout") || document.body;
    if (!target || qs("#laf-roundcube-bridge")) {
      return;
    }

    var wrapper = document.createElement("div");
    wrapper.id = "laf-roundcube-bridge";
    wrapper.style.cssText = "display:flex;gap:8px;align-items:center;padding:10px 12px;margin:10px 0;background:#f8f9fa;border:1px solid #d8dee4;border-radius:8px;";

    var label = document.createElement("strong");
    label.textContent = "Lost & Found";
    wrapper.appendChild(label);

    [
      ["Create Lost", rcmail.env.laf_bridge.create_lost_url],
      ["Create Found", rcmail.env.laf_bridge.create_found_url],
      ["Assign to Existing Item", rcmail.env.laf_bridge.assign_url],
    ].forEach(function (entry) {
      var btn = document.createElement("a");
      btn.href = "#";
      btn.textContent = entry[0];
      btn.style.cssText = "padding:6px 10px;border:1px solid #adb5bd;border-radius:6px;text-decoration:none;color:#212529;background:#fff;";
      btn.addEventListener("click", function (event) {
        event.preventDefault();
        var targetUrl = buildLink(entry[1]);
        if (!targetUrl) {
          window.alert("Please select exactly one message first.");
          return;
        }
        window.open(targetUrl, "_blank");
      });
      wrapper.appendChild(btn);
    });

    target.insertBefore(wrapper, target.firstChild);
  }

  document.addEventListener("DOMContentLoaded", function () {
    addSidebarBackLink();
    addButtonRow();
  });
})();
