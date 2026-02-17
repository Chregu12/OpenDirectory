/**
 * User Entity - Core of Identity Domain
 * Following DDD principles with rich domain model
 */

import { AggregateRoot } from '../../../shared/domain/AggregateRoot';
import { UserId } from '../value-objects/UserId';
import { Username } from '../value-objects/Username';
import { Email } from '../value-objects/Email';
import { Password } from '../value-objects/Password';
import { UserRole } from '../value-objects/UserRole';
import { UserStatus } from '../value-objects/UserStatus';
import { UserCreatedEvent } from '../events/UserCreatedEvent';
import { UserUpdatedEvent } from '../events/UserUpdatedEvent';
import { UserDeactivatedEvent } from '../events/UserDeactivatedEvent';
import { RoleAssignedEvent } from '../events/RoleAssignedEvent';

export interface UserProps {
    username: Username;
    email: Email;
    password: Password;
    firstName?: string;
    lastName?: string;
    roles?: UserRole[];
    status?: UserStatus;
    metadata?: Record<string, any>;
    createdAt?: Date;
    updatedAt?: Date;
}

export class User extends AggregateRoot<UserProps> {
    private constructor(
        id: UserId,
        props: UserProps
    ) {
        super(id, props);
    }

    /**
     * Factory method to create a new user
     */
    public static create(props: UserProps): User {
        const userId = UserId.generate();
        const user = new User(userId, {
            ...props,
            roles: props.roles || [],
            status: props.status || UserStatus.ACTIVE,
            createdAt: props.createdAt || new Date(),
            updatedAt: props.updatedAt || new Date()
        });

        // Emit domain event
        user.addDomainEvent(new UserCreatedEvent({
            aggregateId: userId.toString(),
            username: props.username.toString(),
            email: props.email.toString(),
            occurredAt: new Date()
        }));

        return user;
    }

    /**
     * Reconstitute user from persistence
     */
    public static fromPersistence(
        id: string,
        props: UserProps
    ): User {
        return new User(UserId.fromString(id), props);
    }

    // ==================
    // Business Logic
    // ==================

    /**
     * Assign a role to the user
     */
    public assignRole(role: UserRole): void {
        // Business rule: Cannot assign duplicate roles
        if (this.hasRole(role)) {
            throw new Error(`User already has role: ${role.name}`);
        }

        // Business rule: Cannot exceed max roles
        const MAX_ROLES = 10;
        if (this.props.roles!.length >= MAX_ROLES) {
            throw new Error(`Cannot assign more than ${MAX_ROLES} roles`);
        }

        this.props.roles!.push(role);
        this.props.updatedAt = new Date();

        this.addDomainEvent(new RoleAssignedEvent({
            aggregateId: this.id.toString(),
            userId: this.id.toString(),
            roleName: role.name,
            occurredAt: new Date()
        }));
    }

    /**
     * Remove a role from the user
     */
    public removeRole(role: UserRole): void {
        const index = this.props.roles!.findIndex(r => r.equals(role));
        if (index === -1) {
            throw new Error(`User does not have role: ${role.name}`);
        }

        this.props.roles!.splice(index, 1);
        this.props.updatedAt = new Date();
    }

    /**
     * Check if user has a specific role
     */
    public hasRole(role: UserRole): boolean {
        return this.props.roles!.some(r => r.equals(role));
    }

    /**
     * Check if user has any of the specified roles
     */
    public hasAnyRole(roles: UserRole[]): boolean {
        return roles.some(role => this.hasRole(role));
    }

    /**
     * Update user email
     */
    public changeEmail(newEmail: Email): void {
        // Business rule: Email must be different
        if (this.props.email.equals(newEmail)) {
            throw new Error('New email must be different from current email');
        }

        const oldEmail = this.props.email;
        this.props.email = newEmail;
        this.props.updatedAt = new Date();

        this.addDomainEvent(new UserUpdatedEvent({
            aggregateId: this.id.toString(),
            changes: {
                email: {
                    old: oldEmail.toString(),
                    new: newEmail.toString()
                }
            },
            occurredAt: new Date()
        }));
    }

    /**
     * Update user password
     */
    public changePassword(newPassword: Password): void {
        // Business rule: Password cannot be the same
        if (this.props.password.matches(newPassword.toString())) {
            throw new Error('New password must be different from current password');
        }

        this.props.password = newPassword;
        this.props.updatedAt = new Date();

        this.addDomainEvent(new UserUpdatedEvent({
            aggregateId: this.id.toString(),
            changes: {
                password: 'changed'
            },
            occurredAt: new Date()
        }));
    }

    /**
     * Deactivate user
     */
    public deactivate(): void {
        // Business rule: Cannot deactivate already inactive user
        if (this.props.status === UserStatus.INACTIVE) {
            throw new Error('User is already inactive');
        }

        this.props.status = UserStatus.INACTIVE;
        this.props.updatedAt = new Date();

        this.addDomainEvent(new UserDeactivatedEvent({
            aggregateId: this.id.toString(),
            userId: this.id.toString(),
            reason: 'Manual deactivation',
            occurredAt: new Date()
        }));
    }

    /**
     * Reactivate user
     */
    public reactivate(): void {
        // Business rule: Cannot reactivate active user
        if (this.props.status === UserStatus.ACTIVE) {
            throw new Error('User is already active');
        }

        this.props.status = UserStatus.ACTIVE;
        this.props.updatedAt = new Date();
    }

    /**
     * Lock user account (security)
     */
    public lock(reason: string): void {
        this.props.status = UserStatus.LOCKED;
        this.props.metadata = {
            ...this.props.metadata,
            lockReason: reason,
            lockedAt: new Date()
        };
        this.props.updatedAt = new Date();
    }

    /**
     * Unlock user account
     */
    public unlock(): void {
        if (this.props.status !== UserStatus.LOCKED) {
            throw new Error('User is not locked');
        }

        this.props.status = UserStatus.ACTIVE;
        delete this.props.metadata?.lockReason;
        delete this.props.metadata?.lockedAt;
        this.props.updatedAt = new Date();
    }

    /**
     * Check if user can perform action
     */
    public canPerformAction(action: string): boolean {
        // Business rule: Inactive or locked users cannot perform actions
        if (this.props.status !== UserStatus.ACTIVE) {
            return false;
        }

        // Check role-based permissions
        return this.props.roles!.some(role => 
            role.hasPermission(action)
        );
    }

    // ==================
    // Getters
    // ==================

    get id(): UserId {
        return this._id as UserId;
    }

    get username(): Username {
        return this.props.username;
    }

    get email(): Email {
        return this.props.email;
    }

    get fullName(): string {
        return `${this.props.firstName || ''} ${this.props.lastName || ''}`.trim();
    }

    get roles(): UserRole[] {
        return [...this.props.roles!];
    }

    get status(): UserStatus {
        return this.props.status!;
    }

    get isActive(): boolean {
        return this.props.status === UserStatus.ACTIVE;
    }

    get isLocked(): boolean {
        return this.props.status === UserStatus.LOCKED;
    }

    get createdAt(): Date {
        return this.props.createdAt!;
    }

    get updatedAt(): Date {
        return this.props.updatedAt!;
    }

    /**
     * Convert to plain object for persistence
     */
    public toPersistence(): any {
        return {
            id: this.id.toString(),
            username: this.username.toString(),
            email: this.email.toString(),
            password: this.props.password.toHash(),
            firstName: this.props.firstName,
            lastName: this.props.lastName,
            roles: this.props.roles!.map(r => r.toPersistence()),
            status: this.props.status,
            metadata: this.props.metadata,
            createdAt: this.props.createdAt,
            updatedAt: this.props.updatedAt
        };
    }
}