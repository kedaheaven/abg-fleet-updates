var ABG = ABG || {};
ABG.CommandTemplateFill = (function () {

  // Command Template table logical name (lowercase)
  // This is almost certainly correct given your table name, but if not, change here.
  var TEMPLATE_TABLE = "build_commandtemplate";

  // BayCommand field logical names (lowercase)
  var F_TEMPLATE = "build_commandtemplate";   // lookup on BayCommand
  var F_CMDTYPE  = "build_commandtype";       // choice on BayCommand
  var F_PAYLOAD  = "build_payload";           // text on BayCommand

  // Command Template field logical names (lowercase)
  var T_CMDTYPE  = "build_commandtype";       // choice on Command Template
  var T_PAYLOAD  = "build_defaultpayloadjson";// text on Command Template
  var T_ENABLED  = "build_enabled";           // yes/no on Command Template

  function _getLookupId(lookupValue) {
    if (!lookupValue || !lookupValue.length) return null;
    return lookupValue[0].id.replace("{", "").replace("}", "");
  }

  function _attr(formContext, name) {
    try { return formContext.getAttribute(name); } catch (e) { return null; }
  }

  function _notify(formContext, msg, level) {
    try { formContext.ui.setFormNotification(msg, level || "INFO", "abg_cmdtmpl"); } catch (e) {}
  }

  function _clearNotify(formContext) {
    try { formContext.ui.clearFormNotification("abg_cmdtmpl"); } catch (e) {}
  }

  function applyFromTemplate(executionContext, forcePayload) {
    var formContext = executionContext.getFormContext();

    var tmplAttr   = _attr(formContext, F_TEMPLATE);
    var cmdTypeAttr= _attr(formContext, F_CMDTYPE);
    var payloadAttr= _attr(formContext, F_PAYLOAD);

    if (!tmplAttr) {
      _notify(formContext, "ABG: Field not found on form: " + F_TEMPLATE, "WARNING");
      return;
    }

    var tmplId = _getLookupId(tmplAttr.getValue());
    if (!tmplId) return;

    // DEBUG marker so you know the handler is firing
    _notify(formContext, "ABG: Loading template...", "INFO");

    Xrm.WebApi.retrieveRecord(
      TEMPLATE_TABLE,
      tmplId,
      "?$select=" + [T_CMDTYPE, T_PAYLOAD, T_ENABLED].join(",")
    ).then(function (rec) {

      _clearNotify(formContext);

      if (rec[T_ENABLED] === false) {
        _notify(formContext, "Selected Command Template is disabled.", "WARNING");
      }

      // Always set Command Type from template
      if (cmdTypeAttr && rec[T_CMDTYPE] !== null && rec[T_CMDTYPE] !== undefined) {
        cmdTypeAttr.setValue(parseInt(rec[T_CMDTYPE], 10));
      }

      // Payload: set only if blank unless forcePayload=true
      if (payloadAttr) {
        var cur = payloadAttr.getValue();
        if (forcePayload === true || !cur || cur.trim() === "") {
          payloadAttr.setValue(rec[T_PAYLOAD] || "{}");
        }
      }

    }, function (err) {
      _notify(formContext, "ABG: Template load failed: " + err.message, "WARNING");
    });
  }

  function onTemplateChange(executionContext) {
    applyFromTemplate(executionContext, false);
  }

  function onLoad(executionContext) {
    var formContext = executionContext.getFormContext();
    var tmplAttr = _attr(formContext, F_TEMPLATE);
    if (!tmplAttr || !_getLookupId(tmplAttr.getValue())) return;

    var cmdTypeAttr = _attr(formContext, F_CMDTYPE);
    var payloadAttr = _attr(formContext, F_PAYLOAD);

    var need = false;
    if (cmdTypeAttr && (cmdTypeAttr.getValue() === null || cmdTypeAttr.getValue() === undefined)) need = true;
    if (payloadAttr) {
      var p = payloadAttr.getValue();
      if (!p || p.trim() === "") need = true;
    }

    if (need) applyFromTemplate(executionContext, false);
  }

  return {
    OnLoad: onLoad,
    OnTemplateChange: onTemplateChange,
    ForceApply: function (executionContext) { applyFromTemplate(executionContext, true); }
  };
})();