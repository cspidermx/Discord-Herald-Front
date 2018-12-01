function chgAction(to_change, action_name )
{
    doit = true;
    if (action_name.indexOf('delete') != -1){
        if (confirm("Are you sure you want to delete this rule?")) {
            doit = true;
        } else {
            doit = false;
        }
    }
    if (doit){
        to_change.action = action_name;
        to_change.submit();
    }
}


function supr(url)
{
    if (confirm("Are you sure you want to delete this user?")){
        window.location.replace(url);
    }
}


function confirmstartstop(url)
{
    if (confirm("Confirmation required...")){
        window.location.replace(url);
    }
}



