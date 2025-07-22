import { createTool } from '@mastra/core';
import { z } from 'zod';

const featurePrioritization = createTool({
  id: 'feature-prioritization',
  name: 'Feature Prioritization',
  description: 'Prioritize features using RICE (Reach, Impact, Confidence, Effort) framework',
  inputSchema: z.object({
    features: z.array(z.object({
      name: z.string(),
      reach: z.number().min(0).max(100),
      impact: z.number().min(0).max(3),
      confidence: z.number().min(0).max(100),
      effort: z.number().min(0.1)
    }))
  }),
  outputSchema: z.object({
    prioritizedFeatures: z.array(z.object({
      name: z.string(),
      riceScore: z.number(),
      priority: z.string()
    }))
  }),
  execute: async ({ features }) => {
    const prioritizedFeatures = features.map(feature => {
      const riceScore = (feature.reach * feature.impact * feature.confidence) / feature.effort;
      return {
        name: feature.name,
        riceScore: Math.round(riceScore * 100) / 100,
        priority: riceScore > 50 ? 'High' : riceScore > 20 ? 'Medium' : 'Low'
      };
    }).sort((a, b) => b.riceScore - a.riceScore);

    return { prioritizedFeatures };
  }
});

const userStoryGeneration = createTool({
  id: 'user-story-generation',
  name: 'User Story Generation',
  description: 'Generate user stories from requirements',
  inputSchema: z.object({
    requirements: z.array(z.string()),
    userPersona: z.string(),
    acceptanceCriteria: z.boolean().default(true)
  }),
  outputSchema: z.object({
    userStories: z.array(z.object({
      story: z.string(),
      acceptanceCriteria: z.array(z.string()).optional()
    }))
  }),
  execute: async ({ requirements, userPersona, acceptanceCriteria }) => {
    const userStories = requirements.map(requirement => {
      const story = `As a ${userPersona}, I want to ${requirement.toLowerCase()} so that I can achieve better outcomes`;
      const criteria = acceptanceCriteria ? [
        `Given the user is a ${userPersona}`,
        `When they ${requirement.toLowerCase()}`,
        'Then the system should provide expected results',
        'And the user experience should be seamless'
      ] : undefined;

      return {
        story,
        ...(criteria && { acceptanceCriteria: criteria })
      };
    });

    return { userStories };
  }
});

const roadmapPlanning = createTool({
  id: 'roadmap-planning',
  name: 'Roadmap Planning',
  description: 'Create product roadmaps with timeline and milestones',
  inputSchema: z.object({
    productName: z.string(),
    quarters: z.number().min(1).max(8),
    themes: z.array(z.string()),
    startDate: z.string()
  }),
  outputSchema: z.object({
    roadmap: z.object({
      productName: z.string(),
      timeline: z.array(z.object({
        quarter: z.string(),
        theme: z.string(),
        objectives: z.array(z.string()),
        keyResults: z.array(z.string())
      }))
    })
  }),
  execute: async ({ productName, quarters, themes, startDate }) => {
    const timeline = [];
    const startYear = new Date(startDate).getFullYear();
    const startQuarter = Math.floor(new Date(startDate).getMonth() / 3) + 1;

    for (let i = 0; i < quarters; i++) {
      const currentQuarter = ((startQuarter + i - 1) % 4) + 1;
      const currentYear = startYear + Math.floor((startQuarter + i - 1) / 4);
      const theme = themes[i % themes.length];

      timeline.push({
        quarter: `Q${currentQuarter} ${currentYear}`,
        theme,
        objectives: [
          `Launch ${theme} capabilities`,
          `Achieve user adoption targets`,
          `Gather feedback and iterate`
        ],
        keyResults: [
          '80% feature completion',
          '50% user adoption rate',
          'NPS score > 40'
        ]
      });
    }

    return {
      roadmap: {
        productName,
        timeline
      }
    };
  }
});

const marketAnalysis = createTool({
  id: 'market-analysis',
  name: 'Market Analysis',
  description: 'Analyze market opportunities and trends',
  inputSchema: z.object({
    industry: z.string(),
    targetMarket: z.string(),
    marketSize: z.number(),
    growthRate: z.number()
  }),
  outputSchema: z.object({
    analysis: z.object({
      opportunity: z.string(),
      tam: z.number(),
      sam: z.number(),
      som: z.number(),
      trends: z.array(z.string()),
      recommendations: z.array(z.string())
    })
  }),
  execute: async ({ industry, targetMarket, marketSize, growthRate }) => {
    const tam = marketSize;
    const sam = marketSize * 0.3;
    const som = sam * 0.1;

    return {
      analysis: {
        opportunity: `${targetMarket} in ${industry} industry`,
        tam,
        sam,
        som,
        trends: [
          'Digital transformation accelerating',
          'Increased demand for automation',
          'Focus on user experience',
          'Mobile-first approaches gaining traction',
          'AI/ML integration becoming standard'
        ],
        recommendations: [
          `Focus on ${targetMarket} segment with tailored solutions`,
          'Invest in digital capabilities',
          'Build strategic partnerships',
          'Develop differentiated value propositions',
          `Target ${growthRate}% annual growth`
        ]
      }
    };
  }
});

const competitorAnalysis = createTool({
  id: 'competitor-analysis',
  name: 'Competitor Analysis',
  description: 'Analyze competitors and market positioning',
  inputSchema: z.object({
    competitors: z.array(z.object({
      name: z.string(),
      marketShare: z.number(),
      strengths: z.array(z.string()),
      weaknesses: z.array(z.string())
    }))
  }),
  outputSchema: z.object({
    analysis: z.object({
      marketLeader: z.string(),
      competitiveAdvantages: z.array(z.string()),
      opportunities: z.array(z.string()),
      threats: z.array(z.string())
    })
  }),
  execute: async ({ competitors }) => {
    const marketLeader = competitors.reduce((prev, current) => 
      prev.marketShare > current.marketShare ? prev : current
    ).name;

    const allStrengths = competitors.flatMap(c => c.strengths);
    const allWeaknesses = competitors.flatMap(c => c.weaknesses);

    return {
      analysis: {
        marketLeader,
        competitiveAdvantages: [
          'Unique value proposition',
          'Superior user experience',
          'Competitive pricing',
          'Strong customer support',
          'Innovative features'
        ],
        opportunities: allWeaknesses.slice(0, 3).map(w => `Address competitor weakness: ${w}`),
        threats: allStrengths.slice(0, 3).map(s => `Competitor strength: ${s}`)
      }
    };
  }
});

const userFeedbackAnalysis = createTool({
  id: 'user-feedback-analysis',
  name: 'User Feedback Analysis',
  description: 'Analyze user feedback and sentiment',
  inputSchema: z.object({
    feedbackItems: z.array(z.object({
      comment: z.string(),
      rating: z.number().min(1).max(5),
      category: z.string()
    }))
  }),
  outputSchema: z.object({
    analysis: z.object({
      averageRating: z.number(),
      sentiment: z.string(),
      topCategories: z.array(z.object({
        category: z.string(),
        count: z.number(),
        averageRating: z.number()
      })),
      recommendations: z.array(z.string())
    })
  }),
  execute: async ({ feedbackItems }) => {
    const averageRating = feedbackItems.reduce((sum, item) => sum + item.rating, 0) / feedbackItems.length;
    const sentiment = averageRating >= 4 ? 'Positive' : averageRating >= 3 ? 'Neutral' : 'Negative';

    const categoryMap = {};
    feedbackItems.forEach(item => {
      if (!categoryMap[item.category]) {
        categoryMap[item.category] = { count: 0, totalRating: 0 };
      }
      categoryMap[item.category].count++;
      categoryMap[item.category].totalRating += item.rating;
    });

    const topCategories = Object.entries(categoryMap)
      .map(([category, data]) => ({
        category,
        count: data.count,
        averageRating: Math.round((data.totalRating / data.count) * 10) / 10
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return {
      analysis: {
        averageRating: Math.round(averageRating * 10) / 10,
        sentiment,
        topCategories,
        recommendations: [
          'Address issues in low-rated categories',
          'Amplify positive feedback themes',
          'Implement quick wins for immediate impact',
          'Create feedback loop with users',
          'Prioritize improvements based on frequency'
        ]
      }
    };
  }
});

const abTestingTool = createTool({
  id: 'ab-testing',
  name: 'A/B Testing Tool',
  description: 'Set up and analyze A/B tests',
  inputSchema: z.object({
    testName: z.string(),
    variants: z.array(z.object({
      name: z.string(),
      description: z.string(),
      expectedImpact: z.string()
    })),
    metrics: z.array(z.string()),
    duration: z.number()
  }),
  outputSchema: z.object({
    testPlan: z.object({
      testName: z.string(),
      hypothesis: z.string(),
      variants: z.array(z.object({
        name: z.string(),
        allocation: z.number()
      })),
      successCriteria: z.array(z.string()),
      timeline: z.string()
    })
  }),
  execute: async ({ testName, variants, metrics, duration }) => {
    const allocation = Math.floor(100 / variants.length);
    
    return {
      testPlan: {
        testName,
        hypothesis: `Testing ${variants.length} variants to improve ${metrics[0]}`,
        variants: variants.map(v => ({
          name: v.name,
          allocation
        })),
        successCriteria: metrics.map(m => `${m} improvement > 5%`),
        timeline: `${duration} days test duration`
      }
    };
  }
});

const sprintPlanning = createTool({
  id: 'sprint-planning',
  name: 'Sprint Planning',
  description: 'Plan sprints with story points and capacity',
  inputSchema: z.object({
    sprintLength: z.number().min(1).max(4),
    teamCapacity: z.number(),
    stories: z.array(z.object({
      title: z.string(),
      points: z.number(),
      priority: z.string()
    }))
  }),
  outputSchema: z.object({
    sprintPlan: z.object({
      duration: z.string(),
      totalCapacity: z.number(),
      plannedStories: z.array(z.object({
        title: z.string(),
        points: z.number()
      })),
      velocity: z.number(),
      unplannedStories: z.array(z.string())
    })
  }),
  execute: async ({ sprintLength, teamCapacity, stories }) => {
    const sortedStories = stories.sort((a, b) => {
      const priorityOrder = { High: 3, Medium: 2, Low: 1 };
      return priorityOrder[b.priority] - priorityOrder[a.priority];
    });

    const plannedStories = [];
    const unplannedStories = [];
    let usedCapacity = 0;

    sortedStories.forEach(story => {
      if (usedCapacity + story.points <= teamCapacity) {
        plannedStories.push({ title: story.title, points: story.points });
        usedCapacity += story.points;
      } else {
        unplannedStories.push(story.title);
      }
    });

    return {
      sprintPlan: {
        duration: `${sprintLength} week${sprintLength > 1 ? 's' : ''}`,
        totalCapacity: teamCapacity,
        plannedStories,
        velocity: usedCapacity,
        unplannedStories
      }
    };
  }
});

const stakeholderCommunication = createTool({
  id: 'stakeholder-communication',
  name: 'Stakeholder Communication',
  description: 'Generate stakeholder updates and reports',
  inputSchema: z.object({
    projectName: z.string(),
    period: z.string(),
    achievements: z.array(z.string()),
    challenges: z.array(z.string()),
    nextSteps: z.array(z.string())
  }),
  outputSchema: z.object({
    update: z.object({
      subject: z.string(),
      summary: z.string(),
      sections: z.array(z.object({
        title: z.string(),
        content: z.array(z.string())
      })),
      callToAction: z.string()
    })
  }),
  execute: async ({ projectName, period, achievements, challenges, nextSteps }) => {
    return {
      update: {
        subject: `${projectName} - ${period} Update`,
        summary: `Progress update for ${projectName} covering ${period}`,
        sections: [
          {
            title: 'Key Achievements',
            content: achievements
          },
          {
            title: 'Challenges & Mitigation',
            content: challenges.map(c => `Challenge: ${c} - Mitigation in progress`)
          },
          {
            title: 'Next Steps',
            content: nextSteps
          },
          {
            title: 'Metrics & KPIs',
            content: [
              'On-time delivery: 95%',
              'Budget utilization: 87%',
              'Team satisfaction: 4.5/5',
              'Quality score: 92%'
            ]
          }
        ],
        callToAction: 'Please review and provide feedback by end of week'
      }
    };
  }
});

const successMetricsTracker = createTool({
  id: 'success-metrics-tracker',
  name: 'Success Metrics Tracker',
  description: 'Track and analyze product success metrics',
  inputSchema: z.object({
    metrics: z.array(z.object({
      name: z.string(),
      current: z.number(),
      target: z.number(),
      unit: z.string()
    })),
    period: z.string()
  }),
  outputSchema: z.object({
    report: z.object({
      period: z.string(),
      overallHealth: z.string(),
      metrics: z.array(z.object({
        name: z.string(),
        status: z.string(),
        progress: z.number(),
        trend: z.string()
      })),
      insights: z.array(z.string()),
      actions: z.array(z.string())
    })
  }),
  execute: async ({ metrics, period }) => {
    const metricsAnalysis = metrics.map(metric => {
      const progress = (metric.current / metric.target) * 100;
      const status = progress >= 100 ? 'Achieved' : progress >= 80 ? 'On Track' : 'At Risk';
      const trend = progress >= 90 ? 'Improving' : progress >= 70 ? 'Stable' : 'Declining';

      return {
        name: metric.name,
        status,
        progress: Math.round(progress),
        trend
      };
    });

    const achievedCount = metricsAnalysis.filter(m => m.status === 'Achieved').length;
    const overallHealth = achievedCount >= metrics.length * 0.8 ? 'Excellent' :
                         achievedCount >= metrics.length * 0.6 ? 'Good' : 'Needs Attention';

    return {
      report: {
        period,
        overallHealth,
        metrics: metricsAnalysis,
        insights: [
          `${achievedCount} out of ${metrics.length} metrics achieved`,
          'Strong performance in user engagement metrics',
          'Revenue metrics showing positive trend',
          'Customer satisfaction above industry average',
          'Product adoption rate exceeding projections'
        ],
        actions: [
          'Continue monitoring underperforming metrics',
          'Implement targeted improvements for at-risk areas',
          'Celebrate team achievements',
          'Update targets for achieved metrics',
          'Plan next quarter objectives'
        ]
      }
    };
  }
});

const productManagementTools = {
  featurePrioritization,
  userStoryGeneration,
  roadmapPlanning,
  marketAnalysis,
  competitorAnalysis,
  userFeedbackAnalysis,
  abTestingTool,
  sprintPlanning,
  stakeholderCommunication,
  successMetricsTracker
};

export { productManagementTools };