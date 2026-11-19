import { directoryGroups, DirectoryGroup } from './directoryGroups';
import { employeeInvitationManagement, employeeInvitationManagementError, EmployeeInvitationInput } from './employeeInvitationManagement';

export class EmployeeInvitationActionError extends Error {
  constructor(message: string, public readonly uncertain: boolean, public readonly rollbackComplete: boolean) { super(message); }
}

export async function createEmployeeInvitationWithGroups(input: EmployeeInvitationInput, groups: DirectoryGroup[], signal?: AbortSignal) {
  const added: DirectoryGroup[] = [];
  let pendingReviews = 0; let invitationAttempted = false; let groupMutationUncertain = false;
  const checkActive = () => { if (signal?.aborted) throw new Error('Aufnahme unterbrochen. Bitte den aktuellen Stand prüfen.'); };
  try {
    checkActive();
    if (new Set(groups.map(group => group.id)).size !== groups.length) throw new Error('Doppelte Gruppenauswahl.');
    for (const selected of groups) {
      const current = await directoryGroups.get(selected.id); checkActive();
      if (current.revision !== selected.revision) throw Object.assign(new Error('Gruppenauswahl geändert.'), { response: { status: 412 } });
      if (current.members.includes(input.userId)) continue;
      groupMutationUncertain = true;
      const updated = await directoryGroups.add(current, input.userId);
      groupMutationUncertain = false; added.push(updated); checkActive();
      if (updated.membershipReview?.effective === false) pendingReviews++;
    }
    checkActive(); invitationAttempted = true;
    const result = await employeeInvitationManagement.create(input); checkActive();
    return { ...result, pendingReviews, groupsAdded: added.length };
  } catch (failure: any) {
    const invitationRejected = invitationAttempted && [400, 401, 403, 404, 409, 412, 428, 429].includes(failure?.response?.status);
    const uncertain = groupMutationUncertain || invitationAttempted && !invitationRejected;
    let rollbackComplete = added.length === 0;
    if (!signal?.aborted && !groupMutationUncertain && (!invitationAttempted || invitationRejected)) {
      rollbackComplete = true;
      for (const group of added.reverse()) {
        if (signal?.aborted) { rollbackComplete = false; break; }
        // Use our acknowledged version so a later independent edit cannot be removed.
        try { await directoryGroups.removeMember(group, input.userId); }
        catch { rollbackComplete = false; }
      }
    }
    const message = signal?.aborted ? 'Aufnahme unterbrochen. Bitte den aktuellen Stand prüfen.' : employeeInvitationManagementError(failure);
    const detail = uncertain ? ' Gruppen- oder Einladungsergebnis ist unklar. Mitgliedschaften und Einladungsstatus prüfen, bevor du es erneut versuchst.'
      : added.length ? rollbackComplete ? ' Die bestätigten Gruppenänderungen wurden zurückgenommen.' : ' Die Rücknahme einer Gruppenänderung ist nicht bestätigt. Bitte aktuelle Mitgliedschaften prüfen.' : '';
    throw new EmployeeInvitationActionError(message + detail, uncertain || signal?.aborted === true && added.length > 0, rollbackComplete);
  }
}
