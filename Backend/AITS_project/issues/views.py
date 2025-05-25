from rest_framework import viewsets, permissions, status, generics, filters
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from .models import Issue, Comment, User, Notification
from .serializers import (
    UserSerializer, 
    UserProfileSerializer,
    UserListSerializer,
    IssueSerializer, 
    CommentSerializer,
    NotificationSerializer
)
from .permissions import IsAdminUser, IsAcademicRegistrar, IsLecturer, IsOwnerOrReadOnly

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Additional validation for role-specific fields
        role = serializer.validated_data.get('role')
        if role == User.STUDENT and not serializer.validated_data.get('student_number'):
            return Response(
                {"student_number": "Student number is required for students."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not serializer.validated_data.get('college'):
            if role == User.STUDENT:
                return Response(
                    {"college": "College is required for students."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            elif role in [User.LECTURER, User.ACADEMIC_REGISTRAR]:
                return Response(
                    {"college": "College is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = (permissions.IsAuthenticated,)
    
    def get_object(self):
        return self.request.user

class UserListView(generics.ListAPIView):
    serializer_class = UserListSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filter_backends = [filters.SearchFilter]
    search_fields = ['username', 'first_name', 'last_name', 'email', 'college']
    
    def get_queryset(self):
        role = self.kwargs.get('role') or self.request.query_params.get('role')
        college = self.request.query_params.get('college')
        
        queryset = User.objects.all()
        
        if role:
            queryset = queryset.filter(role=role)
        
        if college:
            queryset = queryset.filter(college=college)
            
        return queryset

class IssueViewSet(viewsets.ModelViewSet):
    queryset = Issue.objects.all()
    serializer_class = IssueSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['title', 'description', 'created_by__username', 'assigned_to__username']
    
    def get_permissions(self):
        if self.action in ['create']:
            permission_classes = [permissions.IsAuthenticated]
        elif self.action in ['update', 'partial_update', 'destroy']:
            permission_classes = [IsOwnerOrReadOnly | IsAdminUser | IsAcademicRegistrar | IsLecturer]
        else:
            permission_classes = [permissions.IsAuthenticated]
        return [permission() for permission in permission_classes]
    
    def get_queryset(self):
        user = self.request.user
        
        # Filter parameters
        status_filter = self.request.query_params.get('status')
        priority_filter = self.request.query_params.get('priority')
        college_filter = self.request.query_params.get('college')
        
        if user.role == User.ADMIN or user.role == User.ACADEMIC_REGISTRAR:
            queryset = Issue.objects.all()
        elif user.role == User.LECTURER:
            # Lecturers see issues assigned to them or created by them
            queryset = Issue.objects.filter(Q(assigned_to=user) | Q(created_by=user))
        else:  # Student
            queryset = Issue.objects.filter(created_by=user)
        
        # Apply filters
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        if priority_filter:
            queryset = queryset.filter(priority=priority_filter)
            
        if college_filter and (user.role == User.ACADEMIC_REGISTRAR or user.role == User.ADMIN):
            queryset = queryset.filter(college=college_filter)
            
        return queryset
    
    @action(detail=True, methods=['post'])
    def assign(self, request, pk=None):
        issue = self.get_object()
        user_id = request.data.get('user_id')
        
        # Check permissions
        if not (request.user.role in [User.ACADEMIC_REGISTRAR, User.ADMIN] or 
                (request.user.role == User.LECTURER and issue.assigned_to == request.user)):
            return Response(
                {"error": "You don't have permission to assign this issue"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if not user_id:
            return Response({"error": "User ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(id=user_id)
            if user.role not in [User.LECTURER, User.ACADEMIC_REGISTRAR, User.ADMIN]:
                return Response({"error": "Can only assign to staff members"}, status=status.HTTP_400_BAD_REQUEST)
            
            issue.assigned_to = user
            issue.save(update_fields=['assigned_to'])
            
            Notification.objects.create(
                user=user,
                notification_type=Notification.ASSIGNED,
                issue=issue,
                message=f"Issue '{issue.title}' has been assigned to you by {request.user.get_full_name()}"
            )
            
            # Notify the creator
            if issue.created_by != request.user and issue.created_by != user:
                Notification.objects.create(
                    user=issue.created_by,
                    notification_type=Notification.ISSUE_UPDATED,
                    issue=issue,
                    message=f"Your issue '{issue.title}' has been assigned to {user.get_full_name()}"
                )
            
            return Response(IssueSerializer(issue).data)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        issue = self.get_object()
        new_status = request.data.get('status')
        
        # Check permissions
        if not (request.user.role in [User.ACADEMIC_REGISTRAR, User.ADMIN] or 
                issue.assigned_to == request.user or 
                issue.created_by == request.user):
            return Response(
                {"error": "You don't have permission to update this issue's status"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if not new_status or new_status not in dict(Issue.STATUS_CHOICES):
            return Response({"error": "Valid status is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        old_status = issue.status
        issue.status = new_status
        issue.save(update_fields=['status'])
        
        # Create notifications
        if issue.created_by != request.user:
            Notification.objects.create(
                user=issue.created_by,
                notification_type=Notification.STATUS_CHANGED,
                issue=issue,
                message=f"Status of your issue '{issue.title}' has been changed to {issue.get_status_display()}"
            )
        
        if issue.assigned_to and issue.assigned_to != request.user and issue.assigned_to != issue.created_by:
            Notification.objects.create(
                user=issue.assigned_to,
                notification_type=Notification.STATUS_CHANGED,
                issue=issue,
                message=f"Status of issue '{issue.title}' has been changed to {issue.get_status_display()}"
            )
        
        return Response({
            "status": "success",
            "message": f"Issue status updated from {old_status} to {new_status}",
            "issue": IssueSerializer(issue).data
        })
    
    @action(detail=True, methods=['post'])
    def update_priority(self, request, pk=None):
        issue = self.get_object()
        new_priority = request.data.get('priority')
        
        # Only academic registrars and admins can update priority
        if not request.user.role in [User.ACADEMIC_REGISTRAR, User.ADMIN]:
            return Response(
                {"error": "Only academic registrars can update issue priority"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if not new_priority or new_priority not in dict(Issue.PRIORITY_CHOICES):
            return Response({"error": "Valid priority is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        old_priority = issue.priority
        issue.priority = new_priority
        issue.save(update_fields=['priority'])
        
        # Create notifications
        if issue.created_by != request.user:
            Notification.objects.create(
                user=issue.created_by,
                notification_type=Notification.ISSUE_UPDATED,
                issue=issue,
                message=f"Priority of your issue '{issue.title}' has been changed to {issue.priority}"
            )
        
        if issue.assigned_to and issue.assigned_to != request.user and issue.assigned_to != issue.created_by:
            Notification.objects.create(
                user=issue.assigned_to,
                notification_type=Notification.ISSUE_UPDATED,
                issue=issue,
                message=f"Priority of issue '{issue.title}' has been changed to {issue.priority}"
            )
        
        return Response({
            "status": "success",
            "message": f"Issue priority updated from {old_priority} to {new_priority}",
            "issue": IssueSerializer(issue).data
        })
    
    @action(detail=True, methods=['post'])
    def request_info(self, request, pk=None):
        issue = self.get_object()
        message = request.data.get('message', 'Additional information is needed to resolve this issue.')
        
        # Check permissions
        if not (request.user.role in [User.ACADEMIC_REGISTRAR, User.ADMIN] or issue.assigned_to == request.user):
            return Response(
                {"error": "You don't have permission to request information for this issue"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Create a comment
        comment = Comment.objects.create(
            issue=issue,
            content=f"REQUEST FOR INFORMATION: {message}",
            created_by=request.user
        )
        
        # Create notification for the student
        Notification.objects.create(
            user=issue.created_by,
            notification_type=Notification.COMMENT_ADDED,
            issue=issue,
            message=f"Additional information requested for your issue '{issue.title}'"
        )
        
        return Response({
            "status": "success",
            "message": "Information request sent to student",
            "comment": CommentSerializer(comment).data
        })
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get statistics about issues for dashboard"""
        user = request.user
        
        # Base queryset depends on user role
        if user.role == User.ADMIN or user.role == User.ACADEMIC_REGISTRAR:
            queryset = Issue.objects.all()
        elif user.role == User.LECTURER:
            queryset = Issue.objects.filter(Q(assigned_to=user) | Q(created_by=user))
        else:  # Student
            queryset = Issue.objects.filter(created_by=user)
        
        # Count issues by status
        status_counts = queryset.values('status').annotate(count=Count('status'))
        
        # Format the response
        stats = {
            'total': queryset.count(),
            'by_status': {item['status']: item['count'] for item in status_counts},
        }
        
        # Add priority stats
        priority_counts = queryset.values('priority').annotate(count=Count('priority'))
        stats['by_priority'] = {item['priority']: item['count'] for item in priority_counts}
        
        # Add college stats for academic registrar
        if user.role in [User.ACADEMIC_REGISTRAR, User.ADMIN]:
            college_counts = queryset.values('college').annotate(count=Count('college'))
            stats['by_college'] = {item['college'] or 'Unknown': item['count'] for item in college_counts}
            
            # Add trend data (issues created in the last 30 days)
            thirty_days_ago = timezone.now() - timedelta(days=30)
            recent_issues = queryset.filter(created_at__gte=thirty_days_ago)
            
            # Group by date
            date_counts = {}
            for issue in recent_issues:
                date_str = issue.created_at.strftime('%Y-%m-%d')
                if date_str in date_counts:
                    date_counts[date_str] += 1
                else:
                    date_counts[date_str] = 1
            
            stats['trend_data'] = date_counts
        
        return Response(stats)
    
    @action(detail=False, methods=['get'])
    def unassigned(self, request):
        """Get unassigned issues - primarily for academic registrars"""
        if not request.user.role in [User.ACADEMIC_REGISTRAR, User.ADMIN]:
            return Response(
                {"error": "Only academic registrars can view unassigned issues list"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        unassigned = Issue.objects.filter(assigned_to__isnull=True).order_by('-created_at')
        
        # Apply filters if provided
        college = request.query_params.get('college')
        if college:
            unassigned = unassigned.filter(college=college)
        
        serializer = IssueSerializer(unassigned, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def report(self, request):
        """Generate reports for academic registrars"""
        if not request.user.role in [User.ACADEMIC_REGISTRAR, User.ADMIN]:
            return Response(
                {"error": "Only academic registrars can generate reports"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        report_type = request.query_params.get('type', 'resolution_time')
        time_period = request.query_params.get('period', '30')  # Default to 30 days
        college = request.query_params.get('college')
        
        try:
            days = int(time_period)
            start_date = timezone.now() - timedelta(days=days)
        except ValueError:
            return Response({"error": "Invalid time period"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Base queryset
        queryset = Issue.objects.filter(created_at__gte=start_date)
        
        # Filter by college if specified
        if college:
            queryset = queryset.filter(college=college)
        
        if report_type == 'resolution_time':
            # Calculate average resolution time for resolved issues
            resolved_issues = queryset.filter(status=Issue.RESOLVED)
            
            total_resolution_time = timedelta()
            resolved_count = 0
            
            for issue in resolved_issues:
                # Calculate time from creation to resolution
                # This is simplified - in a real system you might track when status changed to resolved
                resolution_time = issue.updated_at - issue.created_at
                total_resolution_time += resolution_time
                resolved_count += 1
            
            avg_resolution_time = None
            if resolved_count > 0:
                avg_resolution_time = total_resolution_time / resolved_count
                avg_resolution_hours = avg_resolution_time.total_seconds() / 3600
            else:
                avg_resolution_hours = 0
            
            report_data = {
                'report_type': 'resolution_time',
                'period_days': days,
                'total_issues': queryset.count(),
                'resolved_issues': resolved_count,
                'avg_resolution_time_hours': round(avg_resolution_hours, 2),
                'college': college or 'All colleges'
            }
            
        elif report_type == 'issue_volume':
            # Count issues by status
            status_counts = queryset.values('status').annotate(count=Count('status'))
            
            # Count issues by college
            college_counts = queryset.values('college').annotate(count=Count('college'))
            
            report_data = {
                'report_type': 'issue_volume',
                'period_days': days,
                'total_issues': queryset.count(),
                'by_status': {item['status']: item['count'] for item in status_counts},
                'by_college': {item['college'] or 'Unknown': item['count'] for item in college_counts},
            }
            
        elif report_type == 'lecturer_performance':
            # Get issues assigned to lecturers
            lecturer_issues = queryset.filter(assigned_to__role=User.LECTURER)
            
            # Group by lecturer
            lecturer_stats = {}
            
            for issue in lecturer_issues:
                if not issue.assigned_to:
                    continue
                    
                lecturer_id = issue.assigned_to.id
                lecturer_name = issue.assigned_to.get_full_name()
                
                if lecturer_id not in lecturer_stats:
                    lecturer_stats[lecturer_id] = {
                        'name': lecturer_name,
                        'total': 0,
                        'resolved': 0,
                        'in_progress': 0,
                        'pending': 0,
                        'closed': 0
                    }
                
                lecturer_stats[lecturer_id]['total'] += 1
                
                if issue.status == Issue.RESOLVED:
                    lecturer_stats[lecturer_id]['resolved'] += 1
                elif issue.status == Issue.IN_PROGRESS:
                    lecturer_stats[lecturer_id]['in_progress'] += 1
                elif issue.status == Issue.PENDING:
                    lecturer_stats[lecturer_id]['pending'] += 1
                elif issue.status == Issue.CLOSED:
                    lecturer_stats[lecturer_id]['closed'] += 1
            
            report_data = {
                'report_type': 'lecturer_performance',
                'period_days': days,
                'lecturer_stats': list(lecturer_stats.values())
            }
            
        else:
            return Response({"error": "Invalid report type"}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(report_data)

class CommentViewSet(viewsets.ModelViewSet):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Comment.objects.filter(issue_id=self.kwargs.get('issue_pk'))
    
    def get_permissions(self):
        if self.action in ['update', 'partial_update', 'destroy']:
            permission_classes = [IsOwnerOrReadOnly | IsAdminUser]
        else:
            permission_classes = [permissions.IsAuthenticated]
        return [permission() for permission in permission_classes]
    
    def perform_create(self, serializer):
        issue_id = self.kwargs.get('issue_pk')
        issue = Issue.objects.get(id=issue_id)
        
        comment = serializer.save(
            issue_id=issue_id,
            created_by=self.request.user
        )
        
        # Create notification for the issue creator
        if issue.created_by != self.request.user:
            Notification.objects.create(
                user=issue.created_by,
                notification_type=Notification.COMMENT_ADDED,
                issue=issue,
                message=f"New comment on your issue '{issue.title}'"
            )
        
        # Create notification for the assigned user
        if issue.assigned_to and issue.assigned_to != self.request.user and issue.assigned_to != issue.created_by:
            Notification.objects.create(
                user=issue.assigned_to,
                notification_type=Notification.COMMENT_ADDED,
                issue=issue,
                message=f"New comment on issue '{issue.title}' assigned to you"
            )
        
        return comment

class NotificationViewSet(viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['post'])
    def mark_all_read(self, request):
        notifications = Notification.objects.filter(user=request.user, is_read=False)
        notifications.update(is_read=True)
        return Response({"status": "All notifications marked as read"})
    
    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        notification = self.get_object()
        notification.is_read = True
        notification.save()
        return Response({"status": "Notification marked as read"})
    
    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        count = Notification.objects.filter(user=request.user, is_read=False).count()
        return Response({"count": count})

class CollegesView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        colleges = [
            "College of Computing and Information Sciences",
            "College of Engineering",
            "College of Business and Management Sciences",
            "College of Education and External Studies"
        ]
        return Response(colleges)

class CourseUnitsView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        course_units = [
            "Introduction to Programming",
            "Data Structures and Algorithms",
            "Database Systems",
            "Software Engineering",
            "Computer Networks"
        ]
        return Response(course_units)

class RoleFieldsView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        role = request.query_params.get('role', None)
        
        if not role:
            return Response({"error": "Role parameter is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        if role == User.STUDENT:
            return Response({
                "required_fields": ["student_number", "college", "phone_number"],
                "optional_fields": []
            })
        elif role in [User.LECTURER, User.ACADEMIC_REGISTRAR]:
            return Response({
                "required_fields": ["college", "phone_number"],
                "optional_fields": []
            })
        else:
            return Response({"error": "Invalid role"}, status=status.HTTP_400_BAD_REQUEST)

class DashboardView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        # Base data for all users
        data = {
            'user': {
                'id': user.id,
                'name': user.get_full_name(),
                'role': user.role,
                'college': user.college
            }
        }
        
        # Role-specific data
        if user.role == User.STUDENT:
            # Get student's issues
            issues = Issue.objects.filter(created_by=user)
            data['issues'] = {
                'total': issues.count(),
                'pending': issues.filter(status=Issue.PENDING).count(),
                'in_progress': issues.filter(status=Issue.IN_PROGRESS).count(),
                'resolved': issues.filter(status=Issue.RESOLVED).count(),
                'closed': issues.filter(status=Issue.CLOSED).count(),
            }
            
            # Get recent issues
            recent_issues = issues.order_by('-created_at')[:5]
            data['recent_issues'] = IssueSerializer(recent_issues, many=True).data
            
        elif user.role == User.LECTURER:
            # Get assigned issues
            assigned_issues = Issue.objects.filter(assigned_to=user)
            data['assigned_issues'] = {
                'total': assigned_issues.count(),
                'pending': assigned_issues.filter(status=Issue.PENDING).count(),
                'in_progress': assigned_issues.filter(status=Issue.IN_PROGRESS).count(),
                'resolved': assigned_issues.filter(status=Issue.RESOLVED).count(),
                'closed': assigned_issues.filter(status=Issue.CLOSED).count(),
            }
            
            # Get recent assigned issues
            recent_assigned = assigned_issues.order_by('-created_at')[:5]
            data['recent_assigned'] = IssueSerializer(recent_assigned, many=True).data
            
            # Get issues requiring attention (pending issues)
            pending_issues = assigned_issues.filter(status=Issue.PENDING).order_by('-created_at')[:5]
            data['pending_issues'] = IssueSerializer(pending_issues, many=True).data
            
        elif user.role == User.ACADEMIC_REGISTRAR:
            # Get all issues
            all_issues = Issue.objects.all()
            data['all_issues'] = {
                'total': all_issues.count(),
                'pending': all_issues.filter(status=Issue.PENDING).count(),
                'in_progress': all_issues.filter(status=Issue.IN_PROGRESS).count(),
                'resolved': all_issues.filter(status=Issue.RESOLVED).count(),
                'closed': all_issues.filter(status=Issue.CLOSED).count(),
            }
            
            # Get issues by priority
            data['priority_stats'] = {
                'high': all_issues.filter(priority=Issue.HIGH).count(),
                'medium': all_issues.filter(priority=Issue.MEDIUM).count(),
                'low': all_issues.filter(priority=Issue.LOW).count(),
            }
            
            # Get issues by college
            college_stats = []
            colleges = User.objects.values_list('college', flat=True).distinct()
            for college in colleges:
                if college:  # Skip None values
                    count = Issue.objects.filter(created_by__college=college).count()
                    college_stats.append({'college': college, 'count': count})
            
            data['college_stats'] = college_stats
            
            # Get unassigned issues
            unassigned = Issue.objects.filter(assigned_to__isnull=True).order_by('-created_at')[:5]
            data['unassigned_issues'] = IssueSerializer(unassigned, many=True).data
            
            # Get high priority issues
            high_priority = all_issues.filter(priority=Issue.HIGH).order_by('-created_at')[:5]
            data['high_priority_issues'] = IssueSerializer(high_priority, many=True).data
        
        # Get unread notifications count
        data['unread_notifications'] = Notification.objects.filter(user=user, is_read=False).count()
        
        return Response(data)