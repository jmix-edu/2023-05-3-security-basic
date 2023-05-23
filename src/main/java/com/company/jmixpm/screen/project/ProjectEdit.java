package com.company.jmixpm.screen.project;

import com.company.jmixpm.entity.User;
import io.jmix.core.security.CurrentAuthentication;
import io.jmix.core.usersubstitution.CurrentUserSubstitution;
import io.jmix.ui.screen.*;
import com.company.jmixpm.entity.Project;
import org.springframework.beans.factory.annotation.Autowired;

@UiController("Project.edit")
@UiDescriptor("project-edit.xml")
@EditedEntityContainer("projectDc")
public class ProjectEdit extends StandardEditor<Project> {

    @Autowired
    private CurrentUserSubstitution currentUserSubstitution;

//    @Autowired
//    private CurrentAuthentication currentAuthentication;

    @Subscribe
    public void onInitEntity(InitEntityEvent<Project> event) {
//        User user = (User) currentAuthentication.getUser();
        User user = (User) currentUserSubstitution.getEffectiveUser();
        event.getEntity().setManager(user);
    }
}